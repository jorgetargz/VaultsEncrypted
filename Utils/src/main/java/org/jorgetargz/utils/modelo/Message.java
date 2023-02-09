package org.jorgetargz.utils.modelo;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Message {
    private int id;
    private int idVault;
    private ContentCiphedAES contentCiphedAES;
    private String contentUnsecured;
    private String signedBy;
    private String signature;

    @Override
    public String toString() {
        return "" + id;
    }
}
