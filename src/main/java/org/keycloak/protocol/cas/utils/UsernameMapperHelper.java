package org.keycloak.protocol.cas.utils;

import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.cas.mappers.CASUserMapper;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.Map;

public class UsernameMapperHelper {
    public static String getMappedUsername(KeycloakSession session, AuthenticatedClientSessionModel clientSession) {
        // CAS protocol does not support scopes, so pass null scopeParam
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, null, session);
        UserSessionModel userSession = clientSession.getUserSession();


        Map.Entry<ProtocolMapperModel, ProtocolMapper> mapperPair = ProtocolMapperUtils.getSortedProtocolMappers(session,clientSessionCtx)
                .filter(e -> e.getValue() instanceof CASUserMapper)
                .findFirst()
                .orElse(null);

        String mappedUsername = userSession.getUser().getUsername();

        if(mapperPair != null) {
            ProtocolMapperModel mapping = mapperPair.getKey();
            CASUserMapper casUsernameMapper = (CASUserMapper) mapperPair.getValue();
            mappedUsername = casUsernameMapper.getMappedUsername(mapping, session, userSession, clientSession);
        }
        return mappedUsername;
    }
}