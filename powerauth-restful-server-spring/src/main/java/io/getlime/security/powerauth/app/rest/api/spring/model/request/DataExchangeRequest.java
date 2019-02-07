package io.getlime.security.powerauth.app.rest.api.spring.model.request;

/**
 * Sample model class with request data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class DataExchangeRequest {

    private String data;

    /**
     * Default constructor.
     */
    public DataExchangeRequest() {
    }

    /**
     * Constructor with data.
     * @param data Data.
     */
    public DataExchangeRequest(String data) {
        this.data = data;
    }

    /**
     * Get data.
     * @return Data.
     */
    public String getData() {
        return data;
    }

    /**
     * Set data.
     * @param data Data.
     */
    public void setData(String data) {
        this.data = data;
    }
}
