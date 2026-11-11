package com.produtosapi.controle_sessao;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/usuarios")
public class UsuarioController {

    private final UsuarioRepository repository;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public UsuarioController(UsuarioRepository repository) {
        this.repository = repository;
    }

    public record CadastroRequest(String nome, String email, String senha) {
    }

    public record UsuarioResponse(Long id, String nome, String email) {
    }

    // POST /usuarios
    @PostMapping
    public ResponseEntity<?> cadastrar(@RequestBody CadastroRequest dados) {
        if (vazio(dados.nome()) || vazio(dados.email()) || vazio(dados.senha())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("mensagem", "Informe nome, email e senha."));
        }

        String email = dados.email().trim().toLowerCase();

        if (repository.existsByEmail(email)) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(Map.of("mensagem", "Já existe um usuário com este email."));
        }

        Usuario salvo = repository.save(
                new Usuario(dados.nome().trim(), email, encoder.encode(dados.senha())));

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new UsuarioResponse(salvo.getId(), salvo.getNome(), salvo.getEmail()));
    }

    private boolean vazio(String texto) {
        return texto == null || texto.isBlank();
    }
}