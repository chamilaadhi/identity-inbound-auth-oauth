/*
 * Copyright (c) 2020, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.oauth2.validators.scope;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.core.util.IdentityTenantUtil;
import org.wso2.carbon.identity.oauth.OAuthUtil;
import org.wso2.carbon.identity.oauth.config.OAuthServerConfiguration;
import org.wso2.carbon.identity.oauth.internal.OAuthComponentServiceHolder;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ScopeServerException;
import org.wso2.carbon.identity.oauth2.Oauth2ScopeConstants;
import org.wso2.carbon.identity.oauth2.authz.OAuthAuthzReqMessageContext;
import org.wso2.carbon.identity.oauth2.bean.Scope;
import org.wso2.carbon.identity.oauth2.bean.ScopeBinding;
import org.wso2.carbon.identity.oauth2.dao.OAuthTokenPersistenceFactory;
import org.wso2.carbon.identity.oauth2.token.OAuthTokenReqMessageContext;
import org.wso2.carbon.identity.oauth2.validators.OAuth2TokenValidationMessageContext;
import org.wso2.carbon.user.api.UserStoreException;
import org.wso2.carbon.user.api.UserStoreManager;
import org.wso2.carbon.user.core.service.RealmService;
import org.wso2.carbon.user.core.util.UserCoreUtil;
import org.wso2.carbon.utils.multitenancy.MultitenantUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * This class can be used to check the scopes authorized to the user based on his roles.
 *
 */
public class RoleBasedScopeValidator implements ScopeValidator {
    private static final Log log = LogFactory.getLog(RoleBasedScopeValidator.class);
    private static final String VALIDATOR_NAME = "RoleBasedScopeValidator";

    protected boolean preservedCaseSensitive = true;
    protected String defaultScope;
    protected boolean rejectUnregisteredScopes = false;

    
    @Override
    public boolean canHandle() {
        return OAuthServerConfiguration.getInstance().isRoleBasedScopeValidatorEnabled();
    }

    @Override
    public boolean validateScope(OAuthAuthzReqMessageContext authzReqMessageContext) throws IdentityOAuth2Exception {
        log.info("===== RoleBasedScopeValidator.validateScope(OAuthAuthzReqMessageContext) ======");
        AuthenticatedUser user = authzReqMessageContext.getAuthorizationReqDTO().getUser();
        String[] requestedScopes = authzReqMessageContext.getApprovedScope();
        
        String[] authorizedScopes = validateScope(user, requestedScopes);
        authzReqMessageContext.setApprovedScope(authorizedScopes);
        return true;
    }

    @Override
    public boolean validateScope(OAuthTokenReqMessageContext tokenReqMessageContext) throws IdentityOAuth2Exception {
        log.info("===== RoleBasedScopeValidator.validateScope(OAuthTokenReqMessageContext) ======");
        AuthenticatedUser user = tokenReqMessageContext.getAuthorizedUser();
        String[] requestedScopes = tokenReqMessageContext.getScope();
        
        String[] authorizedScopes = validateScope(user, requestedScopes);
        tokenReqMessageContext.setScope(authorizedScopes);
        return true;
    }

    @Override
    public boolean validateScope(OAuth2TokenValidationMessageContext tokenValidationMessageContext)
            throws IdentityOAuth2Exception {
        log.info("===== RoleBasedScopeValidator.validateScope(OAuth2TokenValidationMessageContext) ======");
        
        AuthenticatedUser user = OAuthUtil
                .getAuthenticatedUser(tokenValidationMessageContext.getResponseDTO().getAuthorizedUser());
        String[] requestedScopes = tokenValidationMessageContext.getResponseDTO().getScope();
      
        String[] authorizedScopes = validateScope(user, requestedScopes);
        tokenValidationMessageContext.getResponseDTO().setScope(authorizedScopes);
        // TODO set 
        return true;
    }

    @Override
    public String getName() {
        return VALIDATOR_NAME;
    }
    
    /**
     * This method is used to get authorized scopes for user from the requested scopes based on roles.
     *
     * @param userRoles Roles list of user
     * @param requestedScopes Requested scopes
     * @param scopeToRoles Scopes to role map
     * @return authorized scopes list
     */
    protected List<String> getAuthorizedScopes(String[] userRoles, String[] requestedScopes,
            Map<String, String> scopeToRoles) {

        List<String> defaultScope = new ArrayList<>();
        //set a default scope if defined. This will be sent if there are no scopes requested.
        if (this.defaultScope != null) {
            defaultScope.add(this.defaultScope);
        }
        
        if (userRoles == null || userRoles.length == 0) {
            userRoles = new String[0];
        }

        List<String> authorizedScopes = new ArrayList<>();

        List<String> userRoleList;
        if (preservedCaseSensitive) {
            userRoleList = Arrays.asList(userRoles);
        } else {
            userRoleList = new ArrayList<>();
            for (String aRole : userRoles) {
                userRoleList.add(aRole.toLowerCase());
            }
        }

        // Iterate the requested scopes list.
        for (String scope : requestedScopes) {

            // If requested scope is not in the binding scope list, we ignore validation for this and set it as a valid
            // scope. This is done to keep the IS default behavior of sending back the requested scope.
            // This behavior could be changed by configuring KEY_REJECT_UNREGISTERED_SCOPES element
            if (!rejectUnregisteredScopes && !scopeToRoles.containsKey(scope)) {
                authorizedScopes.add(scope);
            }

            // Get the set of roles associated with the requested scope.
            String roles = scopeToRoles.get(scope);
            // If the scope has been defined in the context of the App and if roles have been defined for the scope
            if (roles != null && roles.length() != 0) {
                List<String> roleList = new ArrayList<>();
                for (String aRole : roles.split(",")) {
                    if (preservedCaseSensitive) {
                        roleList.add(aRole.trim());
                    } else {
                        roleList.add(aRole.trim().toLowerCase());
                    }
                }
                // Check if user has at least one of the roles associated with the scope
                roleList.retainAll(userRoleList);
                if (!roleList.isEmpty()) {
                    authorizedScopes.add(scope);
                }
            } else if (scopeToRoles.containsKey(scope)) {
                // The requested scope is defined but no roles have been associated with the scope
                authorizedScopes.add(scope);
            }
        }
        return (!authorizedScopes.isEmpty()) ? authorizedScopes : defaultScope;
    }
    
    /**
     * Get scopes to roles mapping using the scopes set.
     * 
     * @param scopes Scope set
     * @return Map of scopes to role mapping. key being the scope and value being the comma separated roles.
     */
    protected Map<String, String> getScopeToRolesMap(Set<Scope> scopes) {
        Map<String, String> scopesMap = new HashMap<String, String>();
        for (Scope scope : scopes) {
            List<ScopeBinding> bindings = scope.getScopeBindings();
            List<String> roleList = new ArrayList<String>();
            boolean hasDefaultBinding = false;
            for (ScopeBinding binding : bindings) {
                if (Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING.equals(binding.getBindingType())) {
                    List<String> bindingRoleList = binding.getBindings();
                    String bindingRoles = StringUtils.join(bindingRoleList.toArray(new String[bindingRoleList.size()]),
                            ",");
                    roleList.add(bindingRoles);
                    hasDefaultBinding = true;
                }
            }
            if (hasDefaultBinding) {
                String roles = StringUtils.join(roleList.toArray(new String[roleList.size()]), ",");
                scopesMap.put(scope.getName(), roles);
            }
        }

        return scopesMap;
    }
    
    /**
     * This method is used to get roles list of the user.
     *
     * @param authenticatedUser Authenticated user
     * @return roles list
     */
    protected String[] getUserRoles(AuthenticatedUser authenticatedUser) {

        String[] userRoles = null;
        String tenantDomain;
        String username;
        Map<ClaimMapping, String> userAttributes = authenticatedUser.getUserAttributes();
        for (Map.Entry<ClaimMapping, String> entry : userAttributes.entrySet()) {
            if (FrameworkConstants.LOCAL_ROLE_CLAIM_URI.equals(entry.getKey().getLocalClaim().getClaimUri())) {
                return entry.getValue().split(FrameworkUtils.getMultiAttributeSeparator());
            }
        }
        
        if (authenticatedUser.isFederatedUser()) {
            tenantDomain = MultitenantUtils.getTenantDomain(authenticatedUser.getAuthenticatedSubjectIdentifier());
            username = MultitenantUtils.getTenantAwareUsername(authenticatedUser.getAuthenticatedSubjectIdentifier());
        } else {
            tenantDomain = authenticatedUser.getTenantDomain();
            username = authenticatedUser.getUserName();
        }
        String userStoreDomain = authenticatedUser.getUserStoreDomain();
        RealmService realmService = OAuthComponentServiceHolder.getInstance().getRealmService();
        try {
            int tenantId = realmService.getTenantManager().getTenantId(tenantDomain);
            // If tenant Id is not set in the tokenReqContext, deriving it from username.
            if (tenantId == 0 || tenantId == -1) {
                tenantId = IdentityTenantUtil.getTenantIdOfUser(username);
            }
            UserStoreManager userStoreManager = realmService.getTenantUserRealm(tenantId).getUserStoreManager();
            String endUsernameWithDomain = UserCoreUtil.addDomainToName(username, userStoreDomain);
            userRoles = userStoreManager.getRoleListOfUser(endUsernameWithDomain);

        } catch (UserStoreException e) {
            // Log and return since we do not want to stop issuing the token in case of scope validation failures.
            log.error("Error when getting the tenant's UserStoreManager or when getting roles of user ", e);
        }
        return userRoles;
    }
    
    
    protected String[] validateScope(AuthenticatedUser authenticatedUser, String[] requestedScopes)
            throws IdentityOAuth2Exception {

        String[] scopes = null;
        List<String> authorizedScopes = null;
        if (log.isDebugEnabled()) {
            log.debug("Requested scopes :" + Arrays.toString(requestedScopes));
        }
        int tenantId = IdentityTenantUtil.getTenantId(authenticatedUser.getTenantDomain());
        try {
            // Get only the scopes with default binding. These scopes are mapped to roles.
            Set<Scope> retrievedScopes = retrieveScopes(tenantId);
            if (retrievedScopes == null || retrievedScopes.isEmpty()) {
                // if there are no scopes with default binding type, no additional validation is done. 
                // This behavior could be changed by configuring KEY_REJECT_UNREGISTERED_SCOPES element
                if (!rejectUnregisteredScopes) {
                    return requestedScopes;
                }
            }
            if (log.isDebugEnabled()) {
                log.debug("Scopes with default binding registered :" + retrievedScopes.toString());
            }
            String[] userRoles = null;

            userRoles = getUserRoles(authenticatedUser);
            if (log.isDebugEnabled()) {
                log.debug("Roles allowed for the user " + authenticatedUser.toString()
                        + " : " + Arrays.toString(userRoles));
            }
            Map<String, String> scopeToRolesMap = getScopeToRolesMap(retrievedScopes);
            if (log.isDebugEnabled()) {
                log.debug("Scope to role mapping : " + (scopeToRolesMap == null ? "{}" : scopeToRolesMap.toString()));
            }
            
            //Get the authorized scopes for the user. user is authorized to have any scopes which are not registered as 
            //DEFAULT type scope. Scopes that are registered will be validated against the user's roles and remove them
            //if not authorized
            authorizedScopes = getAuthorizedScopes(userRoles, requestedScopes, scopeToRolesMap);
            Set<String> authorizedAllScopes = new HashSet<>();
            //To remove duplicates
            authorizedAllScopes.addAll(authorizedScopes);
            if (log.isDebugEnabled()) {
                log.debug("Authorized scopes after validation: "
                        + (authorizedAllScopes == null ? "[]" : authorizedAllScopes.toString()));
            }
            scopes = authorizedAllScopes.toArray(new String[authorizedAllScopes.size()]);
        } catch (IdentityOAuth2ScopeServerException e) {
            log.error("Error while retrieving scopes with default bind type.");
        }

        return scopes;
    }

    protected Set<Scope> retrieveScopes(int tenantId) throws IdentityOAuth2ScopeServerException {
        return OAuthTokenPersistenceFactory.getInstance().getOAuthScopeDAO().getScopes(tenantId,
                Oauth2ScopeConstants.DEFAULT_SCOPE_BINDING);
    }

}
