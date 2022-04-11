package com.example.whizzz.services.model;

public class ChatList {

    private String id;
    private String timestamp;
    private String symmetricKey;

    public ChatList() {

    }

    public ChatList(String id, String timestamp, String symmetricKey) {
        this.id = id;
        this.timestamp = timestamp;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(String timestamp) {
        this.timestamp = timestamp;
    }

    public String getSymmetricKey() {
        return symmetricKey;
    }

    public void setSymmetricKey(String symmetricKey) {
        this.symmetricKey = symmetricKey;
    }
}
