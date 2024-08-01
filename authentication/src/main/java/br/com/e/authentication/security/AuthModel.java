package br.com.e.authentication.security;

public enum AuthModel {

    UsernameAuthModel("UsernameAuthModel"),
    DTeAuthModel("DTeAuthModel"),
    GovBrAuthModel("GovBrAuthModel"),
    AstraAuthModel("AstraAuthModel"),
    ApiKeyAuthModel("ApiKeyAuthModel");;

    private final String model;

    AuthModel(String model)
    {
        this.model = model;
    }

    public String GetModel() { return model;}
    
}
