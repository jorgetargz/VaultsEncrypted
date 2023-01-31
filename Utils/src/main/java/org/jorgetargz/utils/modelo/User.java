package org.jorgetargz.utils.modelo;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class User {
    private String username;
    private String password;
    private String role;
    private ContentCiphedAES publicKeyEncrypted;
    private String encryptedPasswordOfPublicKeyEncrypted;
    private String certificate;
}