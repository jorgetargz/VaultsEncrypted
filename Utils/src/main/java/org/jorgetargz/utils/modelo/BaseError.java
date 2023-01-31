package org.jorgetargz.utils.modelo;

import lombok.AllArgsConstructor;
import lombok.Data;

import java.time.LocalDateTime;

@Data
@AllArgsConstructor
public class BaseError {

    private String message;
    private LocalDateTime fecha;

}
