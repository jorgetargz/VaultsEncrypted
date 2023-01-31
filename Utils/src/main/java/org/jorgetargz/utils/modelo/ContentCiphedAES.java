package org.jorgetargz.utils.modelo;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class ContentCiphedAES {
    private String iv;
    private String salt;
    private String cipherText;
}
