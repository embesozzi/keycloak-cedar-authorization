package com.twogenidentity.keycloak.authorization.cedar;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import org.keycloak.representations.idm.authorization.AbstractPolicyRepresentation;

@JsonIgnoreProperties(ignoreUnknown = true)
public class CedarPolicyRepresentation extends AbstractPolicyRepresentation {

    private String code;

    @Override
    public String getType() {
        return CedarPolicyProviderFactory.PROVIDER_ID;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }
}
