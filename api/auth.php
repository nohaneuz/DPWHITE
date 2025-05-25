<?php
header('Content-Type: application/json');

// Configurações do banco de dados
$db_config = [
    'host' => 'localhost',
    'dbname' => 'dpwhite_db',
    'user' => 'root',
    'password' => ''
];

// Função para conectar ao banco de dados
function conectarDB() {
    global $db_config;
    try {
        $pdo = new PDO(
            "mysql:host={$db_config['host']};dbname={$db_config['dbname']};charset=utf8",
            $db_config['user'],
            $db_config['password'],
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
        );
        return $pdo;
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['erro' => 'Erro de conexão com o banco de dados']);
        exit;
    }
}

// Função para validar e-mail
function validarEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL);
}

// Função para validar senha
function validarSenha($senha) {
    return strlen($senha) >= 8 &&
           preg_match('/[A-Z]/', $senha) &&
           preg_match('/[a-z]/', $senha) &&
           preg_match('/[0-9]/', $senha);
}

// Função para criar hash seguro da senha
function hashSenha($senha) {
    return password_hash($senha, PASSWORD_ARGON2ID);
}

// Função para verificar tentativas de login
function verificarTentativasLogin($email, $ip) {
    $pdo = conectarDB();
    $stmt = $pdo->prepare("SELECT * FROM tentativas_login WHERE email = ? AND ip_address = ?");
    $stmt->execute([$email, $ip]);
    $tentativa = $stmt->fetch();

    if ($tentativa && $tentativa['bloqueado']) {
        $tempo_bloqueio = strtotime($tentativa['ultima_tentativa']) + (15 * 60); // 15 minutos
        if (time() < $tempo_bloqueio) {
            return false;
        }
        // Reseta o bloqueio após 15 minutos
        $stmt = $pdo->prepare("UPDATE tentativas_login SET tentativas = 0, bloqueado = FALSE WHERE id = ?");
        $stmt->execute([$tentativa['id']]);
    }
    return true;
}

// Função para registrar tentativa de login
function registrarTentativaLogin($email, $ip) {
    $pdo = conectarDB();
    $stmt = $pdo->prepare("INSERT INTO tentativas_login (email, ip_address) VALUES (?, ?) ON DUPLICATE KEY UPDATE tentativas = tentativas + 1, ultima_tentativa = CURRENT_TIMESTAMP");
    $stmt->execute([$email, $ip]);

    $stmt = $pdo->prepare("SELECT tentativas FROM tentativas_login WHERE email = ? AND ip_address = ?");
    $stmt->execute([$email, $ip]);
    $tentativas = $stmt->fetchColumn();

    if ($tentativas >= 5) {
        $stmt = $pdo->prepare("UPDATE tentativas_login SET bloqueado = TRUE WHERE email = ? AND ip_address = ?");
        $stmt->execute([$email, $ip]);
    }
}

// Rota para login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['acao']) && $_GET['acao'] === 'login') {
    $data = json_decode(file_get_contents('php://input'), true);
    $email = filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $data['senha'] ?? '';
    $ip = $_SERVER['REMOTE_ADDR'];

    if (!validarEmail($email)) {
        http_response_code(400);
        echo json_encode(['erro' => 'E-mail inválido']);
        exit;
    }

    if (!verificarTentativasLogin($email, $ip)) {
        http_response_code(429);
        echo json_encode(['erro' => 'Muitas tentativas de login. Tente novamente em 15 minutos']);
        exit;
    }

    $pdo = conectarDB();
    $stmt = $pdo->prepare("SELECT id, nome, senha_hash FROM usuarios WHERE email = ? AND ativo = TRUE");
    $stmt->execute([$email]);
    $usuario = $stmt->fetch();

    if (!$usuario || !password_verify($senha, $usuario['senha_hash'])) {
        registrarTentativaLogin($email, $ip);
        http_response_code(401);
        echo json_encode(['erro' => 'E-mail ou senha incorretos']);
        exit;
    }

    // Gera token de sessão
    $token = bin2hex(random_bytes(32));
    $expiracao = date('Y-m-d H:i:s', strtotime('+24 hours'));

    $stmt = $pdo->prepare("INSERT INTO sessoes (usuario_id, token, data_expiracao) VALUES (?, ?, ?)");
    $stmt->execute([$usuario['id'], $token, $expiracao]);

    echo json_encode([
        'token' => $token,
        'nome' => $usuario['nome'],
        'expiracao' => $expiracao
    ]);
}

// Rota para cadastro
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_GET['acao']) && $_GET['acao'] === 'cadastro') {
    $data = json_decode(file_get_contents('php://input'), true);
    $nome = filter_var($data['nome'] ?? '', FILTER_SANITIZE_STRING);
    $email = filter_var($data['email'] ?? '', FILTER_SANITIZE_EMAIL);
    $senha = $data['senha'] ?? '';

    if (strlen($nome) < 3) {
        http_response_code(400);
        echo json_encode(['erro' => 'Nome inválido']);
        exit;
    }

    if (!validarEmail($email)) {
        http_response_code(400);
        echo json_encode(['erro' => 'E-mail inválido']);
        exit;
    }

    if (!validarSenha($senha)) {
        http_response_code(400);
        echo json_encode(['erro' => 'A senha não atende aos requisitos mínimos']);
        exit;
    }

    $pdo = conectarDB();
    
    // Verifica se o e-mail já está cadastrado
    $stmt = $pdo->prepare("SELECT id FROM usuarios WHERE email = ?");
    $stmt->execute([$email]);
    if ($stmt->fetch()) {
        http_response_code(409);
        echo json_encode(['erro' => 'E-mail já cadastrado']);
        exit;
    }

    // Cadastra novo usuário
    $senha_hash = hashSenha($senha);
    $stmt = $pdo->prepare("INSERT INTO usuarios (nome, email, senha_hash) VALUES (?, ?, ?)");
    
    try {
        $stmt->execute([$nome, $email, $senha_hash]);
        echo json_encode(['mensagem' => 'Cadastro realizado com sucesso']);
    } catch (PDOException $e) {
        http_response_code(500);
        echo json_encode(['erro' => 'Erro ao realizar cadastro']);
    }
}

// Rota para verificar autenticação
if ($_SERVER['REQUEST_METHOD'] === 'GET' && isset($_GET['acao']) && $_GET['acao'] === 'verificar') {
    $headers = getallheaders();
    $token = $headers['Authorization'] ?? '';

    if (!$token) {
        http_response_code(401);
        echo json_encode(['erro' => 'Token não fornecido']);
        exit;
    }

    $pdo = conectarDB();
    $stmt = $pdo->prepare(
        "SELECT u.id, u.nome, u.email 
         FROM usuarios u 
         INNER JOIN sessoes s ON u.id = s.usuario_id 
         WHERE s.token = ? AND s.data_expiracao > CURRENT_TIMESTAMP"
    );
    $stmt->execute([$token]);
    $usuario = $stmt->fetch();

    if (!$usuario) {
        http_response_code(401);
        echo json_encode(['erro' => 'Sessão inválida ou expirada']);
        exit;
    }

    echo json_encode([
        'id' => $usuario['id'],
        'nome' => $usuario['nome'],
        'email' => $usuario['email']
    ]);
}