package io.getlime.security.powerauth.app.rest.api.javaee.model.response;

/**
 * Sample model class with response data.
 *
 * @author Roman Strobl, roman.strobl@wultra.com
 */
public class DataExchangeResponse {

    private String data;

    /**
     * Default constructor.
     */
    public DataExchangeResponse() {
    }

    /**
     * Constructor with data.
     * @param data Data.
     */
    public DataExchangeResponse(String data) {
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
