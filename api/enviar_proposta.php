<?php
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

header('Content-Type: application/json');

// --- Configuração --- 
$emailRemetente = 'Pcleste01@gmail.com';
$senhaRemetente = 'pcleste0123@'; // Considere usar uma senha de app
$emailDestinoFixo = 'cotacaodpwhite@gmail.com';

// --- Recebimento dos Dados --- 
$resposta = ['success' => false, 'message' => 'Erro desconhecido.'];

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    $resposta['message'] = 'Método não permitido.';
    echo json_encode($resposta);
    exit;
}

// Recebe o JSON com os dados do formulário
$dadosJson = $_POST['dadosProposta'] ?? null;
if (!$dadosJson) {
    $resposta['message'] = 'Dados da proposta não recebidos.';
    echo json_encode($resposta);
    exit;
}

$dadosProposta = json_decode($dadosJson, true);
if (json_last_error() !== JSON_ERROR_NONE) {
    $resposta['message'] = 'Erro ao decodificar dados da proposta: ' . json_last_error_msg();
    echo json_encode($resposta);
    exit;
}

// --- Preparação do Email --- 
$mail = new PHPMailer(true);

try {
    // Configurações do Servidor SMTP (Gmail)
    $mail->SMTPDebug = SMTP::DEBUG_SERVER; // Habilitar para debug detalhado
    $mail->isSMTP();
    $mail->Host       = 'smtp.gmail.com';
    $mail->SMTPAuth   = true;
    $mail->Username   = $emailRemetente;
    $mail->Password   = $senhaRemetente;
    $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; // Use TLS ou SMTPS
    $mail->Port       = 465; // Porta para SMTPS (ou 587 para TLS)
    $mail->CharSet    = 'UTF-8';

    // Remetente e Destinatários
    $mail->setFrom($emailRemetente, 'DP White VH Seguros - Propostas');

    // Envia PARA o corretor e CC para pcleste01@gmail.com
    $emailCorretor = $dadosProposta['corretorEmail'] ?? null;
    $emailAdicional = 'pcleste01@gmail.com'; // Email fixo adicional

    if ($emailCorretor && filter_var($emailCorretor, FILTER_VALIDATE_EMAIL)) {
        $mail->addAddress($emailCorretor); // Envia TO para o corretor
        $mail->addCC($emailAdicional);     // Envia CC para o email adicional
        error_log("Enviando proposta para: " . $emailCorretor . " (CC: " . $emailAdicional . ")"); // Log
    } else {
        // Se o email do corretor for inválido, envia TO para o email adicional como fallback
        $mail->addAddress($emailAdicional);
        error_log("Email do corretor inválido ou não encontrado: " . $emailCorretor . ". Enviando TO para " . $emailAdicional);
    }

    // Assunto do Email
    $tipoProposta = strtoupper($dadosProposta['tipoProposta'] ?? 'PROPOSTA');
    $nomeCliente = $dadosProposta['titularNome'] ?? ($dadosProposta['empresaRazaoSocial'] ?? 'Cliente');
    $dataEnvio = date('d/m/Y');
    $mail->Subject = "Nova Proposta {$tipoProposta} - {$nomeCliente} - {$dataEnvio}";

    // Corpo do Email (HTML)
    $mail->isHTML(true);
    $corpoEmail = construirCorpoEmailHtml($dadosProposta);
    $mail->Body = $corpoEmail;
    $mail->AltBody = strip_tags($corpoEmail); // Versão texto plano

    // Anexos
    if (!empty($_FILES)) {
        foreach ($_FILES as $key => $file) {
            if ($file['error'] == UPLOAD_ERR_OK) {
                $caminhoTemporario = $file['tmp_name'];
                $nomeOriginal = $file['name'];
                // Adiciona o anexo ao e-mail
                $mail->addAttachment($caminhoTemporario, $nomeOriginal);
            }
        }
    }

    // Envio do Email
    $mail->send();
    $resposta['success'] = true;
    $resposta['message'] = 'Proposta enviada com sucesso por e-mail!';

} catch (Exception $e) {
    $resposta['message'] = "Erro ao enviar e-mail: {$mail->ErrorInfo}";
    error_log("PHPMailer Error: {$mail->ErrorInfo}"); // Log do erro
}

echo json_encode($resposta);

// --- Função Auxiliar para Construir o Corpo do Email --- 
function construirCorpoEmailHtml($dados) {
    $html = "<html><head><style>body{font-family: sans-serif;} table{width: 100%; border-collapse: collapse;} th, td{border: 1px solid #ddd; padding: 8px; text-align: left;} th{background-color: #f2f2f2;}</style></head><body>";
    $html .= "<h1>Detalhes da Proposta</h1>";

    // Itera sobre os dados e cria seções/tabelas
    foreach ($dados as $chave => $valor) {
        if (is_array($valor)) {
            // Se for um array (ex: corretor, empresa, dependentes), cria uma tabela
            $tituloSecao = ucwords(str_replace(['-', '_'], ' ', $chave));
            $html .= "<h2>{$tituloSecao}</h2>";
            $html .= "<table>";
            foreach ($valor as $subChave => $subValor) {
                if (!is_array($subValor)) { // Não exibe sub-arrays aninhados por enquanto
                   $label = ucwords(str_replace(['-', '_'], ' ', $subChave));
                   $html .= "<tr><th>{$label}</th><td>" . htmlspecialchars($subValor ?: 'Não informado') . "</td></tr>";
                }
                 // Tratamento especial para dependentes ou sócios (se forem arrays de objetos)
                 elseif ($chave === 'dependentes' || $chave === 'socios') {
                    $html .= "<tr><td colspan='2'>";
                    foreach($subValor as $index => $item) {
                        $itemTitulo = ucwords(rtrim($chave, 's')) . " " . ($index + 1);
                        $html .= "<strong>{$itemTitulo}:</strong> ";
                        $detalhesItem = [];
                        foreach($item as $itemChave => $itemValor) {
                            $detalhesItem[] = ucwords($itemChave) . ": " . htmlspecialchars($itemValor ?: 'N/A');
                        }
                        $html .= implode(', ', $detalhesItem) . "<br>";
                    }
                    $html .= "</td></tr>";
                 }
            }
            $html .= "</table>";
        } else {
            // Se for um valor simples, adiciona como linha
            // Evita exibir chaves que contêm 'arquivo-' pois os arquivos vão como anexo
             if (strpos($chave, 'arquivo-') === false) {
                 if (!isset($dadosAgrupados)) {
                     $html .= "<h2>Outras Informações</h2><table>";
                     $dadosAgrupados = true;
                 }
                 $label = ucwords(str_replace(['-', '_'], ' ', $chave));
                 $html .= "<tr><th>{$label}</th><td>" . htmlspecialchars($valor ?: 'Não informado') . "</td></tr>";
             }
        }
    }
     if (isset($dadosAgrupados)) {
         $html .= "</table>";
     }

    $html .= "<p>Proposta gerada em: " . date('d/m/Y H:i:s') . "</p>";
    $html .= "</body></html>";
    return $html;
}

?>
