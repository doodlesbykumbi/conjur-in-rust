extern crate aes_gcm;
extern crate chacha20poly1305;
extern crate hex_literal;
extern crate ctr;

#[cfg(test)]
mod tests {
    use chacha20poly1305::{
        aead::{AeadCore, OsRng, Error},
        ChaCha20Poly1305, Nonce
    };
    use aes_gcm::{
        aes::cipher::{
            KeyInit,
        },
        aead::{Aead, generic_array::GenericArray, Payload},
        Aes256Gcm,
    };
    use ctr::cipher::{
        KeyIvInit,
        StreamCipher,
    };
    use hex_literal::hex;
    

    fn unpack(raw_packed: &[u8]) -> (&[u8], &[u8],  &[u8]) {
        let mut index = 1;
        let mut next_index = index + 16; // tag size
        let raw_tag = &raw_packed[index..next_index];
    
        index = next_index;
        next_index = index + 12; // iv/nonce size
        let raw_nonce = &raw_packed[index..next_index];
    
        index = next_index;
        let raw_ciphertext = &raw_packed[index..] as &[u8];
    
        return (raw_nonce, raw_ciphertext, raw_tag);
    }

    type Aes256Ctr128BE = ctr::Ctr128BE<aes_gcm::aes::Aes256>;
    fn aes256_ctr(key: &[u8], iv: &[u8], text: &[u8]) ->  Result<Vec<u8>, Error> {
        let mut buf = Vec::from(text);
        let mut iv = Vec::from(iv);
        iv.extend_from_slice(&[0, 0, 0, 2]);

        let mut cipher = Aes256Ctr128BE::new(key.into(), iv.as_slice().into());
        cipher.apply_keystream(&mut buf);

        Ok(buf)
    }

    #[test]
    fn aes_gcm_decryption_works() {
        let key = &hex!("d803ff3786a33d8debb23a5a21a8238c0f891e30db230fa123eb88df68e7acfe");
        let packed = &hex!("47545e57ad5dd125c7f5206e2b7dbd12bc10e17cf62fca1e336a306961ab2678a47e0f4ae87b4ffae9babb91fdef8e15a34391b663");
        let aad =  b"myConjurAccount:variable:BotApp/secretVar";
        let expected_plaintext = b"5f7bd49c1e68a0fe0f9ab216";

        let key = GenericArray::from_slice(key);
        let (nonce, ciphertext, tag) = unpack(packed);
    
        let mut ciphertext = Vec::from(ciphertext);
        ciphertext.extend_from_slice(tag);
        let payload = Payload {
            msg: &ciphertext,
            aad: aad,
        };
        let nonce = GenericArray::from_slice(nonce);

        // Decrypt
        let cipher = Aes256Gcm::new(key);
        let plaintext_result = cipher.decrypt(nonce, payload);

        let plaintext = match plaintext_result {
            Ok(value) => value,
            Err(error) => panic!("Problem decrypting: {:?}", error),
        };

        assert_eq!(expected_plaintext, plaintext.as_slice());

        // Decrypt without verification
        // AES-GCM without verification simply becomes AES-CTR, with a 12-byte nonce for GCM being converted to a 16-byte IV for CTR by
        // taking the nonce and appending the following 4 bytes [0,0,0,2]
        let packed = &hex!("ab2678a47e0f4ae87b4ffae9babb91fdef8e15a34391b663");
        let plaintext = aes256_ctr(key, nonce, packed).unwrap();
        assert_eq!(expected_plaintext, plaintext.as_slice());

        // Re-encrypt without verification
        let ciphertext = aes256_ctr(key, nonce, plaintext.as_slice()).unwrap();
        assert_eq!(packed, ciphertext.as_slice());
    }

    #[test]
    fn chacha_works() {
        let key = &hex!("d803ff3786a33d8debb23a5a21a8238c0f891e30db230fa123eb88df68e7acfe");
        let aad =  b"myConjurAccount:variable:BotApp/secretVar";
        let plaintext = b"some secret";

        let key = GenericArray::from_slice(key);
        let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
        let nonce = Nonce::from_slice(&nonce); 


        let cipher = ChaCha20Poly1305::new(key);

        // Encryption 
        let payload = Payload {
            msg: plaintext,
            aad: aad,
        };
        let ciphertext = cipher.encrypt(nonce, payload).unwrap();
        
        // Decryption
        let payload = Payload {
            msg: &ciphertext,
            aad: aad,
        };
        let plaintext_result = cipher.decrypt(nonce, payload);
        let plaintext = match plaintext_result {
            Ok(value) => value,
            Err(error) => panic!("Problem decrypting: {:?}", error),
        };

        assert_eq!(plaintext, b"some secret");
    }
}
