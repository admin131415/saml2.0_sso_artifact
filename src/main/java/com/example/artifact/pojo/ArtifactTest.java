package com.example.artifact.pojo;

public class ArtifactTest {
    private String typeCode;
    private String sourceId;
    private String messageHandler;
    private String endpointIndex;

    public String getTypeCode() {
        return typeCode;
    }

    public void setTypeCode(String typeCode) {
        this.typeCode = typeCode;
    }

    public String getSourceId() {
        return sourceId;
    }

    public void setSourceId(String sourceId) {
        this.sourceId = sourceId;
    }

    public String getMessageHandler() {
        return messageHandler;
    }

    public void setMessageHandler(String messageHandler) {
        this.messageHandler = messageHandler;
    }

    public String getEndpointIndex() {
        return endpointIndex;
    }

    public void setEndpointIndex(String endpointIndex) {
        this.endpointIndex = endpointIndex;
    }

    public ArtifactTest() {
    }

    @Override
    public String toString() {
        return "ArtifactTest{" +
                "typeCode='" + typeCode + '\'' +
                ", sourceId='" + sourceId + '\'' +
                ", messageHandler='" + messageHandler + '\'' +
                ", endpointIndex='" + endpointIndex + '\'' +
                '}';
    }

    public ArtifactTest(String typeCode, String sourceId, String messageHandler, String endpointIndex) {
        this.typeCode = typeCode;
        this.sourceId = sourceId;
        this.messageHandler = messageHandler;
        this.endpointIndex = endpointIndex;
    }
}
