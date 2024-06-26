package org.keycloak.protocol.cas.mappers;

import org.keycloak.Config;
import org.keycloak.models.*;
import org.keycloak.protocol.ProtocolMapper;
import org.keycloak.protocol.ProtocolMapperUtils;
import org.keycloak.protocol.cas.CASLoginProtocol;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;

public class CASUserMapper implements ProtocolMapper {
    public static final String PROVIDER_ID = "cas-usermodel-user-mapper";
    public static final String USERNAME_MAPPER_CATEGORY = "CAS User Mapper";
    private static final String CONF_FALLBACK_TO_USERNAME_IF_NULL = "user_fallback";

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<ProviderConfigProperty>();
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ProtocolMapperUtils.USER_ATTRIBUTE);
        property.setLabel(ProtocolMapperUtils.USER_MODEL_PROPERTY_LABEL);
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setHelpText(ProtocolMapperUtils.USER_MODEL_PROPERTY_HELP_TEXT);
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(CONF_FALLBACK_TO_USERNAME_IF_NULL);
        property.setLabel("Use username if attribute is missing");
        property.setHelpText("Should the User's username be used if the specified attribute is blank?");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        property.setDefaultValue(false);
        configProperties.add(property);


    }

    @Override
    public String getProtocol() {
        return CASLoginProtocol.LOGIN_PROTOCOL;
    }

    @Override
    public void close() {
    }

    @Override
    public final ProtocolMapper create(KeycloakSession session) {
        throw new RuntimeException("UNSUPPORTED METHOD");
    }
    
    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public final String getDisplayCategory() {
        return USERNAME_MAPPER_CATEGORY;
    }

    @Override
    public final String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "User Attribute Mapper For CAS User";
    }

    @Override
    public String getHelpText() {
        return "Maps a user attribute to CAS User value.";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    public String getMappedUsername(ProtocolMapperModel mappingModel, KeycloakSession session,
                                    UserSessionModel userSession, AuthenticatedClientSessionModel clientSession) {

        boolean defaultIfNull = Boolean.parseBoolean(mappingModel.getConfig().get(CONF_FALLBACK_TO_USERNAME_IF_NULL));
        UserModel user = userSession.getUser();
        String mappedUsername = user.getFirstAttribute(mappingModel.getConfig().get(ProtocolMapperUtils.USER_ATTRIBUTE));

        if(mappedUsername == null && defaultIfNull) {
            mappedUsername = user.getUsername();
        }
        return mappedUsername;
    }
}