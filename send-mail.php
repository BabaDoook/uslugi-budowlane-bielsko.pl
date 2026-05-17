<?php
header('Content-Type: application/json; charset=UTF-8');

function clean_input($data) {
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    return $data;
}

if ($_SERVER["REQUEST_METHOD"] !== "POST") {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Metoda niedozwolona.']);
    exit;
}

// Honeypot
if (!empty($_POST['website'])) {
    echo json_encode(['success' => true, 'message' => 'Wiadomość wysłana pomyślnie.']);
    exit;
}

$imie    = clean_input($_POST['imie']      ?? '');
$telefon = clean_input($_POST['telefon']   ?? '');
$email   = clean_input($_POST['email']     ?? '');
$usluga  = clean_input($_POST['usluga']    ?? '');
$wiad    = clean_input($_POST['wiadomosc'] ?? '');
$rodo    = !empty($_POST['rodo']);

if (empty($imie) || empty($telefon) || empty($usluga) || empty($wiad) || !$rodo) {
    http_response_code(400);
    echo json_encode(['success' => false, 'message' => 'Proszę wypełnić wszystkie wymagane pola.']);
    exit;
}

$to          = 'skupbud@gmail.com';
$raw_subject = "Nowe zapytanie: $usluga – $imie";
$subject     = '=?UTF-8?B?' . base64_encode($raw_subject) . '?=';

$body  = "Nowe zapytanie ze strony uslugi-budowlane-bielsko.pl\n\n";
$body .= "Imie i nazwisko : $imie\n";
$body .= "Telefon         : $telefon\n";
$body .= "E-mail          : " . (!empty($email) ? $email : "(nie podano)") . "\n";
$body .= "Rodzaj uslugi   : $usluga\n\n";
$body .= "Opis zlecenia:\n$wiad\n\n";
$body .= "---\nData: " . date('d.m.Y H:i:s') . "\nZgoda RODO: TAK\n";

$headers  = "MIME-Version: 1.0\r\n";
$headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
$headers .= "From: no-reply@uslugi-budowlane-bielsko.pl\r\n";
$headers .= "Reply-To: " . (!empty($email) ? $email : $to) . "\r\n";
$headers .= "X-Mailer: PHP/" . phpversion();

if (mail($to, $subject, $body, $headers)) {
    echo json_encode(['success' => true, 'message' => 'Dziękujemy! Wiadomość wysłana. Skontaktujemy się wkrótce.']);
} else {
    http_response_code(500);
    echo json_encode(['success' => false, 'message' => 'Błąd wysyłania. Prosimy o kontakt: 570 039 889.']);
}
?>
