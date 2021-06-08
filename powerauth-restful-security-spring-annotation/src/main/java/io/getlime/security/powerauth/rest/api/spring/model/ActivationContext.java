package io.getlime.security.powerauth.rest.api.spring.model;

import com.wultra.security.powerauth.client.v3.ActivationStatus;

import javax.xml.datatype.XMLGregorianCalendar;
import java.util.List;

/**
 * Class representing the activation context data. It maps detailed activation attributes
 * to a class that is supposed to be used by the developers in various scenarios.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
public class ActivationContext {
    
    private String activationId;
    private String activationName;
    private List<String> activationFlags;
    private ActivationStatus activationStatus;
    private String blockedReason;
    private long applicationId;
    private String userId;
    private long version;
    private XMLGregorianCalendar timestampCreated;
    private XMLGregorianCalendar timestampLastUsed;
    private XMLGregorianCalendar timestampLastChange;
    private String platform;
    private String deviceInfo;
    private String extras;

    /**
     * Set activation ID.
     * @param activationId Activation ID.
     */
    public void setActivationId(String activationId) {
        this.activationId = activationId;
    }

    /**
     * Get activation ID.
     * @return Activation ID.
     */
    public String getActivationId() {
        return activationId;
    }

    /**
     * Set activation name.
     * @param activationName Activation name.
     */
    public void setActivationName(String activationName) {
        this.activationName = activationName;
    }

    /**
     * Get activation name.
     * @return Activation name.
     */
    public String getActivationName() {
        return activationName;
    }

    /**
     * Set activation flags.
     * @param activationFlags Activation flags.
     */
    public void setActivationFlags(List<String> activationFlags) {
        this.activationFlags = activationFlags;
    }

    /**
     * Get activation flags.
     * @return Activation flags.
     */
    public List<String> getActivationFlags() {
        return activationFlags;
    }

    /**
     * Set activation status.
     * @param activationStatus Activation status.
     */
    public void setActivationStatus(ActivationStatus activationStatus) {
        this.activationStatus = activationStatus;
    }

    /**
     * Get activation status.
     * @return Activation status.
     */
    public ActivationStatus getActivationStatus() {
        return activationStatus;
    }

    /**
     * Set blocked reason.
     * @param blockedReason Blocked reason.
     */
    public void setBlockedReason(String blockedReason) {
        this.blockedReason = blockedReason;
    }

    /**
     * Get blocked reason.
     * @return Blocked reason.
     */
    public String getBlockedReason() {
        return blockedReason;
    }

    /**
     * Set application ID.
     * @param applicationId Application ID.
     */
    public void setApplicationId(long applicationId) {
        this.applicationId = applicationId;
    }

    /**
     * Get application ID.
     * @return Application ID.
     */
    public long getApplicationId() {
        return applicationId;
    }

    /**
     * Set user ID.
     * @param userId User ID.
     */
    public void setUserId(String userId) {
        this.userId = userId;
    }

    /**
     * Get user ID.
     * @return User ID.
     */
    public String getUserId() {
        return userId;
    }

    /**
     * Set version.
     * @param version Version.
     */
    public void setVersion(long version) {
        this.version = version;
    }

    /**
     * Get version.
     * @return Version.
     */
    public long getVersion() {
        return version;
    }

    /**
     * Set timestamp created.
     * @param timestampCreated Timestamp created.
     */
    public void setTimestampCreated(XMLGregorianCalendar timestampCreated) {
        this.timestampCreated = timestampCreated;
    }

    /**
     * Get timestamp created.
     * @return Timestamp created.
     */
    public XMLGregorianCalendar getTimestampCreated() {
        return timestampCreated;
    }

    /**
     * Set timestamp last used.
     * @param timestampLastUsed Timestamp last used.
     */
    public void setTimestampLastUsed(XMLGregorianCalendar timestampLastUsed) {
        this.timestampLastUsed = timestampLastUsed;
    }

    /**
     * Get timestamp last used.
     * @return Timestamp last used.
     */
    public XMLGregorianCalendar getTimestampLastUsed() {
        return timestampLastUsed;
    }

    /**
     * Set timestamp last change.
     * @param timestampLastChange Timestamp last change.
     */
    public void setTimestampLastChange(XMLGregorianCalendar timestampLastChange) {
        this.timestampLastChange = timestampLastChange;
    }

    /**
     * Get timestamp last change.
     * @return Timestamp last change.
     */
    public XMLGregorianCalendar getTimestampLastChange() {
        return timestampLastChange;
    }

    /**
     * Set platform.
     * @param platform Platform.
     */
    public void setPlatform(String platform) {
        this.platform = platform;
    }

    /**
     * Get platform.
     * @return Platform.
     */
    public String getPlatform() {
        return platform;
    }

    /**
     * Set device info.
     * @param deviceInfo Device info.
     */
    public void setDeviceInfo(String deviceInfo) {
        this.deviceInfo = deviceInfo;
    }

    /**
     * Get device info.
     * @return Device info.
     */
    public String getDeviceInfo() {
        return deviceInfo;
    }

    /**
     * Set extras.
     * @param extras Extras.
     */
    public void setExtras(String extras) {
        this.extras = extras;
    }

    /**
     * Get extras.
     * @return Extras.
     */
    public String getExtras() {
        return extras;
    }
}
