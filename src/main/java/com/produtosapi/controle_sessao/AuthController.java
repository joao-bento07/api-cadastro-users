package com.produtosapi.controle_sessao;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

@RestController
public class AuthController {

    private static final int SEGUNDOS_DE_SESSAO = 60;

    private final UsuarioRepository repository;
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();

    public AuthController(UsuarioRepository repository) {
        this.repository = repository;
    }

    public record LoginRequest(String email, String senha) {
    }

    // POST /login
    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> login(@RequestBody LoginRequest dados,
                                                     HttpServletRequest request) {
        if (vazio(dados.email()) || vazio(dados.senha())) {
            return ResponseEntity.badRequest()
                    .body(Map.of("mensagem", "Informe email e senha."));
        }

        Optional<Usuario> encontrado = repository.findByEmail(dados.email().trim().toLowerCase());

        if (encontrado.isEmpty() || !encoder.matches(dados.senha(), encontrado.get().getSenha())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("mensagem", "Email ou senha inválidos."));
        }

        // descarta qualquer sessão anterior e cria uma nova
        HttpSession antiga = request.getSession(false);
        if (antiga != null) {
            antiga.invalidate();
        }

        HttpSession sessao = request.getSession(true);
        sessao.setMaxInactiveInterval(SEGUNDOS_DE_SESSAO);
        sessao.setAttribute("usuarioId", encontrado.get().getId());
        sessao.setAttribute("loginEm", Instant.now());

        return ResponseEntity.ok(
                Map.of("mensagem", "Login realizado. Acesso concedido por 1 minuto."));
    }

    // GET /protegido
    @GetMapping("/protegido")
    public ResponseEntity<Map<String, String>> protegido(HttpServletRequest request) {
        HttpSession sessao = request.getSession(false);

        if (sessao == null) {
            return naoLogado();
        }

        Instant loginEm = (Instant) sessao.getAttribute("loginEm");

        // a janela é de 1 minuto a partir do login, mesmo que o usuário continue acessando
        if (loginEm == null
                || Duration.between(loginEm, Instant.now()).getSeconds() >= SEGUNDOS_DE_SESSAO) {
            sessao.invalidate();
            return naoLogado();
        }

        return ResponseEntity.ok(Map.of("mensagem", "Acesso garantido!"));
    }

    private ResponseEntity<Map<String, String>> naoLogado() {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body(Map.of("mensagem", "Você não está logado. Faça login para acessar esta rota."));
    }

    private boolean vazio(String texto) {
        return texto == null || texto.isBlank();
    }
}