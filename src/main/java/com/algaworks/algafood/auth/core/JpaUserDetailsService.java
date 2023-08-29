package com.algaworks.algafood.auth.core;

import com.algaworks.algafood.auth.domain.Usuario;
import com.algaworks.algafood.auth.domain.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@RequiredArgsConstructor
@Service                    //UserDetailsService faz o Spring consultar o usuário
public class JpaUserDetailsService implements UserDetailsService {

    private final UsuarioRepository usuarioRepository;
    private static final String MSG_USER_NOT_FOUND = "Usuário não encontrado com e-mail informado";

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Usuario usuario = usuarioRepository.findByEmail(username)
                .orElseThrow(() -> new UsernameNotFoundException(MSG_USER_NOT_FOUND));

        return new AuthUser(usuario);
    }
}
