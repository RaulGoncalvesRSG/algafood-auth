package com.algaworks.algafood.auth.core;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;

import java.util.HashMap;

//Classe para adicionar Claims (informações de chave e valor no no payload do token JWT) costumizadas
public class JwtCustomClaimsTokenEnhancer implements TokenEnhancer {

	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		//Verufucação para garantir a instância de AuthUser, pois se n for, lança exceção
		if (authentication.getPrincipal() instanceof AuthUser) {
			AuthUser authUser = (AuthUser) authentication.getPrincipal();

			HashMap<String, Object> info = new HashMap<>();		//Claims costumizadas
			info.put("nome_completo", authUser.getFullName());
			info.put("usuario_id", authUser.getUserId());

			DefaultOAuth2AccessToken oAuth2AccessToken = (DefaultOAuth2AccessToken) accessToken;
			oAuth2AccessToken.setAdditionalInformation(info);
		}
		return accessToken;			//Retorna o accessToken modificado
	}

}
