package org.keycloak.protocol.cas.utils;

import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.cas.mappers.CASUserMapper;
import org.keycloak.services.util.DefaultClientSessionContext;

import java.util.Map;

public class UserMapperHelper {
    public static String getMappedUser(KeycloakSession session, AuthenticatedClientSessionModel clientSession) {
        // CAS protocol does not support scopes, so pass null scopeParam
        ClientSessionContext clientSessionCtx = DefaultClientSessionContext.fromClientSessionAndScopeParameter(clientSession, null, session);
        UserSessionModel userSession = clientSession.getUserSession();


        Map.Entry<ProtocolMapperModel, ProtocolMapper> mapperPair = ProtocolMapperUtils.getSortedProtocolMappers(session,clientSessionCtx)
                .filter(e -> e.getValue() instanceof CASUserMapper)
                .findFirst()
                .orElse(null);

        String mappedUser = userSession.getUser().getUsername();

        if(mapperPair != null) {
            ProtocolMapperModel mapping = mapperPair.getKey();
            CASUserMapper casUserMapper = (CASUserMapper) mapperPair.getValue();
            mappedUser = casUserMapper.getMappedUsername(mapping, session, userSession, clientSession);
        }
        return mappedUser;
    }
}