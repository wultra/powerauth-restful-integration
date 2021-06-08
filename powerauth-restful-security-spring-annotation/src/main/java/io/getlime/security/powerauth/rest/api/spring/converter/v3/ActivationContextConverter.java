package io.getlime.security.powerauth.rest.api.spring.converter.v3;

import com.wultra.security.powerauth.client.v3.GetActivationStatusResponse;
import io.getlime.security.powerauth.rest.api.spring.model.ActivationContext;
import org.springframework.stereotype.Component;

/**
 * Converter class for conversions of activation context.
 *
 * @author Petr Dvorak, petr@wultra.com
 */
@Component
public class ActivationContextConverter {

    /**
     * Convert new activation context from activation status response.
     *
     * @param source Activation status response.
     * @return Activation context.
     */
    public ActivationContext fromActivationDetailResponse(GetActivationStatusResponse source) {
        final ActivationContext destination = new ActivationContext();
        destination.setActivationId(source.getActivationId());
        destination.setActivationName(source.getActivationName());
        destination.setActivationFlags(source.getActivationFlags());
        destination.setActivationStatus(source.getActivationStatus());
        destination.setBlockedReason(source.getBlockedReason());
        destination.setApplicationId(source.getApplicationId());
        destination.setUserId(source.getUserId());
        destination.setVersion(source.getVersion());
        destination.setTimestampCreated(source.getTimestampCreated());
        destination.setTimestampLastUsed(source.getTimestampLastUsed());
        destination.setTimestampLastChange(source.getTimestampLastChange());
        destination.setPlatform(source.getPlatform());
        destination.setDeviceInfo(source.getDeviceInfo());
        destination.setExtras(source.getExtras());
        return destination;
    }

}
