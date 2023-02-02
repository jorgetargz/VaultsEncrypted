package org.jorgetargz.utils.modelo;

import lombok.*;

@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Vault {
    private int id;
    private String name;
    private String usernameOwner;
    private String key;
    private boolean readByAll;
    private boolean writeByAll;

    @Override
    public String toString() {
        return this.name;
    }
}
