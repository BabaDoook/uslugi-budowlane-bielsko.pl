<?php
/**
 * send-mail.php – Bezpieczny handler formularza kontaktowego
 * KUBAR Maciej Kubica | skupbud@gmail.com
 *
 * Zabezpieczenia:
 *  - Honeypot anti-spam
 *  - Rate limiting (max 5 wysyłek / 10 min per IP, zapis w pliku)
 *  - Walidacja i sanityzacja wszystkich pól
 *  - Ochrona przed header injection
 *  - Tylko metoda POST
 *  - JSON response
 */

declare(strict_types=1);

/* ════════════════════════════════════════
   KONFIGURACJA — zmień według potrzeb
════════════════════════════════════════ */
const MAIL_TO        = 'skupbud@gmail.com';
const MAIL_FROM_NAME = 'Formularz KUBAR';
const MAIL_SUBJECT   = '[KUBAR] Nowe zapytanie ze strony';
const RATE_LIMIT_MAX = 5;           // maks. wysyłek per IP
const RATE_LIMIT_WIN = 600;         // okno czasowe w sekundach (10 min)
const RATE_FILE_DIR  = __DIR__ . '/rate_limits/'; // katalog do zapisu (poza public_html jeśli możliwe)
/* ════════════════════════════════════════ */

header('Content-Type: application/json; charset=UTF-8');
header('X-Content-Type-Options: nosniff');

/* ── Tylko POST ── */
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['success' => false, 'message' => 'Niedozwolona metoda.']);
    exit;
}

/* ── Pomocnik odpowiedzi ── */
function respond(bool $ok, string $msg, int $code = 200): void
{
    http_response_code($code);
    echo json_encode(['success' => $ok, 'message' => $msg]);
    exit;
}

/* ── Sanityzacja (nie strip_tags – usuwamy tylko niebezpieczne znaki) ── */
function clean(string $val): string
{
    return htmlspecialchars(trim($val), ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

/* ── Ochrona przed header injection ── */
function safeHeader(string $val): string
{
    return preg_replace('/[\r\n\t]/', '', $val);
}

/* ── Rate limiting per IP ── */
function checkRateLimit(string $ip): bool
{
    if (!is_dir(RATE_FILE_DIR)) {
        @mkdir(RATE_FILE_DIR, 0750, true);
        // Zabezpieczenie przed bezpośrednim dostępem
        file_put_contents(RATE_FILE_DIR . '.htaccess', 'deny from all');
    }

    $file = RATE_FILE_DIR . md5($ip) . '.json';
    $now  = time();
    $data = [];

    if (file_exists($file)) {
        $raw = file_get_contents($file);
        $data = json_decode($raw, true) ?: [];
    }

    // usuń stare wpisy poza oknem czasowym
    $data = array_filter($data, fn($t) => ($now - $t) < RATE_LIMIT_WIN);

    if (count($data) >= RATE_LIMIT_MAX) {
        return false; // przekroczony limit
    }

    $data[] = $now;
    file_put_contents($file, json_encode(array_values($data)), LOCK_EX);
    return true;
}

/* ════════════════════════════════════════
   HONEYPOT — boty wypełniają ukryte pole
════════════════════════════════════════ */
if (!empty($_POST['website'])) {
    // Cicha akceptacja (bot nie wie, że coś się nie powiodło)
    respond(true, 'Wiadomość wysłana.');
}

/* ════════════════════════════════════════
   RATE LIMITING
════════════════════════════════════════ */
$ip = $_SERVER['HTTP_CF_CONNECTING_IP']    // Cloudflare
   ?? $_SERVER['HTTP_X_FORWARDED_FOR']
   ?? $_SERVER['REMOTE_ADDR']
   ?? '0.0.0.0';

// Weź tylko pierwszy IP z listy (X-Forwarded-For może być wieloczłonowy)
$ip = explode(',', $ip)[0];
$ip = filter_var(trim($ip), FILTER_VALIDATE_IP) ? trim($ip) : '0.0.0.0';

if (!checkRateLimit($ip)) {
    respond(false, 'Zbyt wiele wiadomości w krótkim czasie. Odczekaj chwilę i spróbuj ponownie, lub zadzwoń: 570 039 889.', 429);
}

/* ════════════════════════════════════════
   POBRANIE I WALIDACJA PÓL
════════════════════════════════════════ */
$imie    = clean($_POST['imie']    ?? '');
$telefon = clean($_POST['telefon'] ?? '');
$email   = trim($_POST['email']    ?? '');
$usluga  = clean($_POST['usluga']  ?? '');
$wiad    = clean($_POST['wiadomosc'] ?? '');
$rodo    = !empty($_POST['rodo']);

/* Wymagane pola */
if (!$imie || !$telefon || !$usluga || !$wiad) {
    respond(false, 'Proszę wypełnić wszystkie wymagane pola.', 400);
}

/* Długości */
if (mb_strlen($imie) > 100) respond(false, 'Imię jest zbyt długie.', 400);
if (mb_strlen($telefon) > 20) respond(false, 'Numer telefonu jest zbyt długi.', 400);
if (mb_strlen($usluga) > 100) respond(false, 'Nieprawidłowy rodzaj usługi.', 400);
if (mb_strlen($wiad) > 3000) respond(false, 'Opis jest zbyt długi (max 3000 znaków).', 400);

/* Telefon – tylko cyfry, spacje, +, -, () */
if (!preg_match('/^[\d\s\+\-\(\)]{7,20}$/', $telefon)) {
    respond(false, 'Podaj poprawny numer telefonu.', 400);
}

/* E-mail – opcjonalny, ale jeśli podany to musi być prawidłowy */
$emailSafe = '';
if ($email !== '') {
    $emailFiltered = filter_var($email, FILTER_VALIDATE_EMAIL);
    if (!$emailFiltered || mb_strlen($email) > 150) {
        respond(false, 'Podaj poprawny adres e-mail lub pozostaw pole puste.', 400);
    }
    $emailSafe = $emailFiltered;
}

/* Zgoda RODO */
if (!$rodo) {
    respond(false, 'Wymagana jest zgoda na przetwarzanie danych osobowych.', 400);
}

/* ════════════════════════════════════════
   BUDOWANIE WIADOMOŚCI
════════════════════════════════════════ */
$emailLine  = $emailSafe ? $emailSafe : '(nie podano)';
$ipSafe     = htmlspecialchars($ip, ENT_QUOTES, 'UTF-8');
$dateSafe   = date('d.m.Y H:i:s');

$body = <<<EOT
Nowe zapytanie ze strony KUBAR
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Imię i nazwisko : {$imie}
Telefon         : {$telefon}
E-mail          : {$emailLine}
Rodzaj usługi   : {$usluga}

Opis zlecenia:
{$wiad}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Data wysyłki : {$dateSafe}
IP nadawcy   : {$ipSafe}
Zgoda RODO   : TAK
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Wiadomość wygenerowana automatycznie przez stronę KUBAR.
EOT;

/* ════════════════════════════════════════
   NAGŁÓWKI MAILA
════════════════════════════════════════ */
$subjectEncoded = '=?UTF-8?B?' . base64_encode(MAIL_SUBJECT . ' – ' . $usluga) . '?=';

$fromName = safeHeader(MAIL_FROM_NAME);
$headers  = implode("\r\n", [
    'From: ' . $fromName . ' <noreply@' . ($_SERVER['HTTP_HOST'] ?? 'twojadomena.pl') . '>',
    'Reply-To: ' . ($emailSafe ?: MAIL_TO),
    'MIME-Version: 1.0',
    'Content-Type: text/plain; charset=UTF-8',
    'Content-Transfer-Encoding: 8bit',
    'X-Mailer: PHP/' . PHP_VERSION,
]);

/* ════════════════════════════════════════
   WYSYŁKA
════════════════════════════════════════ */
$sent = mail(MAIL_TO, $subjectEncoded, $body, $headers);

if ($sent) {
    respond(true, 'Wiadomość została wysłana. Skontaktujemy się wkrótce!');
} else {
    // Logowanie błędu (nie ujawniamy szczegółów klientowi)
    error_log('[KUBAR MAIL ERROR] mail() failed for IP: ' . $ip . ' at ' . $dateSafe);
    respond(false, 'Niestety nie udało się wysłać wiadomości. Proszę zadzwonić bezpośrednio: 570 039 889.', 500);
}
