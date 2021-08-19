package com.security.cryptograph.domain;

import java.io.Serializable;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class Country implements Serializable {

    private final String name;
    private final String currency;

}
