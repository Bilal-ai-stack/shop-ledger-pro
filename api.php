<?php
// ════════════════════════════════════════════════════════
//  Shop Ledger Pro — Backend API
//  © 2025 Shop Ledger Pro. All rights reserved.
//  Place this file in your Hostinger public_html folder
// ════════════════════════════════════════════════════════

header('Content-Type: application/json');
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: POST, GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, X-Session-Token');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') { http_response_code(200); exit; }

// ── DB CONFIG — fill these in ─────────────────────────
define('DB_HOST', 'localhost');
define('DB_NAME', 'dukan_khata');
define('DB_USER', 'bilal_ahmad');
define('DB_PASS', 'Bilalahmad@0313');

// ── Connect ───────────────────────────────────────────
function db() {
    static $pdo = null;
    if ($pdo) return $pdo;
    try {
        $pdo = new PDO(
            'mysql:host='.DB_HOST.';dbname='.DB_NAME.';charset=utf8mb4',
            DB_USER, DB_PASS,
            [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
             PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC]
        );
    } catch (Exception $e) {
        resp(['error' => 'DB connection failed: '.$e->getMessage()], 500);
    }
    return $pdo;
}

function resp($data, $code=200) {
    http_response_code($code);
    echo json_encode($data);
    exit;
}

function err($msg, $code=400) {
    resp(['error' => $msg], $code);
}

// ── Install DB schema ─────────────────────────────────
function install() {
    $db = db();
    $db->exec("
    CREATE TABLE IF NOT EXISTS businesses (
        id INT AUTO_INCREMENT PRIMARY KEY,
        name VARCHAR(255) NOT NULL,
        currency VARCHAR(10) DEFAULT '₨',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        business_id INT NOT NULL,
        username VARCHAR(100) NOT NULL,
        pin_hash VARCHAR(255) NOT NULL,
        role ENUM('owner','manager','staff') DEFAULT 'staff',
        status ENUM('active','disabled','pending') DEFAULT 'active',
        last_login DATETIME NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        UNIQUE KEY uniq_user (business_id, username),
        FOREIGN KEY (business_id) REFERENCES businesses(id)
    );

    CREATE TABLE IF NOT EXISTS sessions (
        token VARCHAR(64) PRIMARY KEY,
        user_id INT NOT NULL,
        business_id INT NOT NULL,
        expires_at DATETIME NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS customers (
        id INT AUTO_INCREMENT PRIMARY KEY,
        business_id INT NOT NULL,
        name VARCHAR(255) NOT NULL,
        phone VARCHAR(50) DEFAULT '',
        address TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        outstanding DECIMAL(12,2) DEFAULT 0.00,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id)
    );

    CREATE TABLE IF NOT EXISTS transactions (
        id INT AUTO_INCREMENT PRIMARY KEY,
        business_id INT NOT NULL,
        customer_id INT NOT NULL,
        user_id INT NOT NULL,
        type ENUM('debt','credit') NOT NULL,
        amount DECIMAL(12,2) NOT NULL,
        tx_date DATE NOT NULL,
        note TEXT DEFAULT '',
        items JSON DEFAULT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id),
        FOREIGN KEY (customer_id) REFERENCES customers(id),
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
        id INT AUTO_INCREMENT PRIMARY KEY,
        business_id INT NOT NULL,
        user_id INT NOT NULL,
        action VARCHAR(100) NOT NULL,
        detail TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (business_id) REFERENCES businesses(id)
    );
    ");
}

// ── Auth helpers ──────────────────────────────────────
function hashPin($pin) {
    return hash('sha256', $pin . 'slp_salt_2025');
}

function getSession() {
    $token = $_SERVER['HTTP_X_SESSION_TOKEN'] ?? ($_GET['token'] ?? '');
    if (!$token) return null;
    $db = db();
    $st = $db->prepare("SELECT s.*, u.role, u.username, u.status FROM sessions s JOIN users u ON s.user_id=u.id WHERE s.token=? AND s.expires_at > NOW()");
    $st->execute([$token]);
    $row = $st->fetch();
    if (!$row || $row['status'] !== 'active') return null;
    return $row;
}

function requireAuth($minRole = null) {
    $s = getSession();
    if (!$s) err('Not authenticated', 401);
    $roles = ['staff' => 1, 'manager' => 2, 'owner' => 3];
    if ($minRole && ($roles[$s['role']] ?? 0) < ($roles[$minRole] ?? 0)) {
        err('Insufficient permissions', 403);
    }
    return $s;
}

function audit($sess, $action, $detail='') {
    $db = db();
    $st = $db->prepare("INSERT INTO audit_log (business_id,user_id,action,detail) VALUES (?,?,?,?)");
    $st->execute([$sess['business_id'], $sess['user_id'], $action, $detail]);
}

// ── Router ────────────────────────────────────────────
$body = json_decode(file_get_contents('php://input'), true) ?? [];
$action = $body['action'] ?? $_GET['action'] ?? '';

switch ($action) {

    // ── SETUP: First-time install ─────────────────────
    case 'setup':
        install();
        $db = db();
        // Check if any business exists
        $exists = $db->query("SELECT COUNT(*) as c FROM businesses")->fetch()['c'];
        if ($exists > 0) err('Already set up');
        $shopName = trim($body['shopName'] ?? 'My Shop');
        $ownerUser = trim($body['username'] ?? 'admin');
        $ownerPin  = trim($body['pin'] ?? '');
        if (!$ownerPin || strlen($ownerPin) < 4) err('PIN must be at least 4 digits');
        $db->prepare("INSERT INTO businesses (name) VALUES (?)")->execute([$shopName]);
        $bizId = $db->lastInsertId();
        $db->prepare("INSERT INTO users (business_id,username,pin_hash,role,status) VALUES (?,?,?,'owner','active')")
           ->execute([$bizId, $ownerUser, hashPin($ownerPin)]);
        resp(['ok' => true, 'message' => 'Shop Ledger Pro installed successfully!']);

    // ── LOGIN ─────────────────────────────────────────
    case 'login':
        install();
        $db = db();
        $username = trim($body['username'] ?? '');
        $pin      = trim($body['pin'] ?? '');
        $st = $db->prepare("SELECT u.*, b.name as bizName, b.currency FROM users u JOIN businesses b ON u.business_id=b.id WHERE u.username=? AND u.pin_hash=?");
        $st->execute([$username, hashPin($pin)]);
        $user = $st->fetch();
        if (!$user) err('Wrong username or PIN', 401);
        if ($user['status'] === 'disabled') err('Your account has been disabled. Contact your admin.', 403);
        if ($user['status'] === 'pending') err('Your account is pending approval.', 403);
        // Create session
        $token = bin2hex(random_bytes(32));
        $db->prepare("INSERT INTO sessions (token,user_id,business_id,expires_at) VALUES (?,?,?,DATE_ADD(NOW(), INTERVAL 8 HOUR))")
           ->execute([$token, $user['id'], $user['business_id']]);
        $db->prepare("UPDATE users SET last_login=NOW() WHERE id=?")->execute([$user['id']]);
        resp(['ok'=>true,'token'=>$token,'role'=>$user['role'],'username'=>$user['username'],'bizName'=>$user['bizName'],'currency'=>$user['currency'],'userId'=>$user['id'],'bizId'=>$user['business_id']]);

    // ── LOGOUT ────────────────────────────────────────
    case 'logout':
        $sess = requireAuth();
        db()->prepare("DELETE FROM sessions WHERE token=?")->execute([$_SERVER['HTTP_X_SESSION_TOKEN'] ?? '']);
        resp(['ok'=>true]);

    // ── GET ALL CUSTOMERS ─────────────────────────────
    case 'getCustomers':
        $sess = requireAuth();
        $db = db();
        $st = $db->prepare("SELECT * FROM customers WHERE business_id=? ORDER BY name ASC");
        $st->execute([$sess['business_id']]);
        $customers = $st->fetchAll();
        // Get transactions for each
        foreach ($customers as &$c) {
            $ts = $db->prepare("SELECT t.*, u.username as added_by FROM transactions t JOIN users u ON t.user_id=u.id WHERE t.customer_id=? ORDER BY t.tx_date ASC, t.id ASC");
            $ts->execute([$c['id']]);
            $txs = $ts->fetchAll();
            foreach ($txs as &$tx) {
                $tx['items'] = $tx['items'] ? json_decode($tx['items'], true) : [];
            }
            $c['transactions'] = $txs;
        }
        resp(['ok'=>true,'customers'=>$customers,'ts'=>time()]);

    // ── ADD CUSTOMER ──────────────────────────────────
    case 'addCustomer':
        $sess = requireAuth('staff');
        $db = db();
        $name = trim($body['name'] ?? '');
        if (!$name) err('Name required');
        // Check duplicate
        $dup = $db->prepare("SELECT id FROM customers WHERE business_id=? AND name=?");
        $dup->execute([$sess['business_id'], $name]);
        if ($dup->fetch()) err('Customer already exists');
        $db->prepare("INSERT INTO customers (business_id,name,phone,address,notes) VALUES (?,?,?,?,?)")
           ->execute([$sess['business_id'], $name, $body['phone']??'', $body['address']??'', $body['notes']??'']);
        $id = $db->lastInsertId();
        audit($sess, 'add_customer', $name);
        resp(['ok'=>true,'id'=>$id]);

    // ── UPDATE CUSTOMER ───────────────────────────────
    case 'updateCustomer':
        $sess = requireAuth('staff');
        $db = db();
        $id = intval($body['id'] ?? 0);
        // Verify ownership
        $chk = $db->prepare("SELECT id FROM customers WHERE id=? AND business_id=?");
        $chk->execute([$id, $sess['business_id']]);
        if (!$chk->fetch()) err('Customer not found', 404);
        $field = $body['field'] ?? '';
        $allowed = ['name','phone','address','notes'];
        if (!in_array($field, $allowed)) err('Invalid field');
        $db->prepare("UPDATE customers SET $field=? WHERE id=? AND business_id=?")
           ->execute([$body['value']??'', $id, $sess['business_id']]);
        audit($sess, 'update_customer', "$field for customer #$id");
        resp(['ok'=>true]);

    // ── DELETE CUSTOMER ───────────────────────────────
    case 'deleteCustomer':
        $sess = requireAuth('manager');
        $db = db();
        $id = intval($body['id'] ?? 0);
        $chk = $db->prepare("SELECT name FROM customers WHERE id=? AND business_id=?");
        $chk->execute([$id, $sess['business_id']]);
        $c = $chk->fetch();
        if (!$c) err('Customer not found', 404);
        $db->prepare("DELETE FROM transactions WHERE customer_id=? AND business_id=?")->execute([$id, $sess['business_id']]);
        $db->prepare("DELETE FROM customers WHERE id=? AND business_id=?")->execute([$id, $sess['business_id']]);
        audit($sess, 'delete_customer', $c['name']);
        resp(['ok'=>true]);

    // ── ADD TRANSACTION (DEBT) ────────────────────────
    case 'addDebt':
        $sess = requireAuth('staff');
        $db = db();
        $custId = intval($body['customerId'] ?? 0);
        $items  = $body['items'] ?? [];
        $date   = $body['date'] ?? date('Y-m-d');
        if (!$custId || !$items) err('Invalid data');
        // Verify customer belongs to this business
        $chk = $db->prepare("SELECT id,outstanding FROM customers WHERE id=? AND business_id=?");
        $chk->execute([$custId, $sess['business_id']]);
        $cust = $chk->fetch();
        if (!$cust) err('Customer not found', 404);
        $total = array_sum(array_map(fn($i)=>($i['qty']??1)*($i['price']??0), $items));
        if ($total <= 0) err('Total must be greater than 0');
        $db->prepare("INSERT INTO transactions (business_id,customer_id,user_id,type,amount,tx_date,items) VALUES (?,?,?,'debt',?,?,?)")
           ->execute([$sess['business_id'], $custId, $sess['user_id'], $total, $date, json_encode($items)]);
        $db->prepare("UPDATE customers SET outstanding=outstanding+? WHERE id=?")->execute([$total, $custId]);
        audit($sess, 'add_debt', "Customer #$custId amount=$total");
        resp(['ok'=>true,'total'=>$total]);

    // ── ADD TRANSACTION (CREDIT) ──────────────────────
    case 'addCredit':
        $sess = requireAuth('staff');
        $db = db();
        $custId = intval($body['customerId'] ?? 0);
        $amount = floatval($body['amount'] ?? 0);
        $note   = trim($body['note'] ?? 'Payment received');
        $date   = $body['date'] ?? date('Y-m-d');
        if (!$custId || $amount <= 0) err('Invalid data');
        $chk = $db->prepare("SELECT id,outstanding FROM customers WHERE id=? AND business_id=?");
        $chk->execute([$custId, $sess['business_id']]);
        $cust = $chk->fetch();
        if (!$cust) err('Customer not found', 404);
        $newBal = max(0, $cust['outstanding'] - $amount);
        $db->prepare("INSERT INTO transactions (business_id,customer_id,user_id,type,amount,tx_date,note) VALUES (?,?,?,'credit',?,?,?)")
           ->execute([$sess['business_id'], $custId, $sess['user_id'], $amount, $date, $note]);
        $db->prepare("UPDATE customers SET outstanding=? WHERE id=?")->execute([$newBal, $custId]);
        audit($sess, 'add_credit', "Customer #$custId amount=$amount");
        resp(['ok'=>true,'newBalance'=>$newBal]);

    // ── DELETE TRANSACTION ────────────────────────────
    case 'deleteTransaction':
        $sess = requireAuth('manager');
        $db = db();
        $txId = intval($body['txId'] ?? 0);
        $st = $db->prepare("SELECT t.*,c.outstanding FROM transactions t JOIN customers c ON t.customer_id=c.id WHERE t.id=? AND t.business_id=?");
        $st->execute([$txId, $sess['business_id']]);
        $tx = $st->fetch();
        if (!$tx) err('Transaction not found', 404);
        $adj = $tx['type']==='debt' ? -$tx['amount'] : $tx['amount'];
        $newBal = max(0, $tx['outstanding'] + $adj);
        $db->prepare("DELETE FROM transactions WHERE id=?")->execute([$txId]);
        $db->prepare("UPDATE customers SET outstanding=? WHERE id=?")->execute([$newBal, $tx['customer_id']]);
        audit($sess, 'delete_transaction', "TxID=$txId type={$tx['type']} amount={$tx['amount']}");
        resp(['ok'=>true]);

    // ── GET USERS (owner only) ────────────────────────
    case 'getUsers':
        $sess = requireAuth('owner');
        $st = db()->prepare("SELECT id,username,role,status,last_login,created_at FROM users WHERE business_id=? ORDER BY role DESC, username ASC");
        $st->execute([$sess['business_id']]);
        resp(['ok'=>true,'users'=>$st->fetchAll()]);

    // ── ADD USER ──────────────────────────────────────
    case 'addUser':
        $sess = requireAuth('owner');
        $db = db();
        $uname = trim($body['username'] ?? '');
        $pin   = trim($body['pin'] ?? '');
        $role  = in_array($body['role']??'', ['manager','staff']) ? $body['role'] : 'staff';
        if (!$uname) err('Username required');
        if (strlen($pin) < 4) err('PIN must be at least 4 digits');
        $dup = $db->prepare("SELECT id FROM users WHERE business_id=? AND username=?");
        $dup->execute([$sess['business_id'], $uname]);
        if ($dup->fetch()) err('Username already exists');
        $db->prepare("INSERT INTO users (business_id,username,pin_hash,role,status) VALUES (?,?,?,?,'active')")
           ->execute([$sess['business_id'], $uname, hashPin($pin), $role]);
        audit($sess, 'add_user', "$uname role=$role");
        resp(['ok'=>true]);

    // ── UPDATE USER ───────────────────────────────────
    case 'updateUser':
        $sess = requireAuth('owner');
        $db = db();
        $uid    = intval($body['userId'] ?? 0);
        $status = in_array($body['status']??'', ['active','disabled']) ? $body['status'] : null;
        $role   = in_array($body['role']??'', ['owner','manager','staff']) ? $body['role'] : null;
        $pin    = trim($body['pin'] ?? '');
        // Cannot modify own account role/status
        if ($uid === intval($sess['user_id'])) err('Cannot modify your own account');
        // Verify user belongs to this business
        $chk = $db->prepare("SELECT id,username FROM users WHERE id=? AND business_id=?");
        $chk->execute([$uid, $sess['business_id']]);
        $u = $chk->fetch();
        if (!$u) err('User not found', 404);
        if ($status) { $db->prepare("UPDATE users SET status=? WHERE id=?")->execute([$status, $uid]); }
        if ($role)   { $db->prepare("UPDATE users SET role=? WHERE id=?")->execute([$role, $uid]); }
        if ($pin && strlen($pin) >= 4) { $db->prepare("UPDATE users SET pin_hash=? WHERE id=?")->execute([hashPin($pin), $uid]); }
        audit($sess, 'update_user', "User {$u['username']} status=$status role=$role");
        resp(['ok'=>true]);

    // ── DELETE USER ───────────────────────────────────
    case 'deleteUser':
        $sess = requireAuth('owner');
        $db = db();
        $uid = intval($body['userId'] ?? 0);
        if ($uid === intval($sess['user_id'])) err('Cannot delete yourself');
        $chk = $db->prepare("SELECT username FROM users WHERE id=? AND business_id=?");
        $chk->execute([$uid, $sess['business_id']]);
        $u = $chk->fetch();
        if (!$u) err('User not found', 404);
        $db->prepare("DELETE FROM sessions WHERE user_id=?")->execute([$uid]);
        $db->prepare("DELETE FROM users WHERE id=?")->execute([$uid]);
        audit($sess, 'delete_user', $u['username']);
        resp(['ok'=>true]);

    // ── GET AUDIT LOG ─────────────────────────────────
    case 'getAuditLog':
        $sess = requireAuth('owner');
        $st = db()->prepare("SELECT a.*, u.username FROM audit_log a JOIN users u ON a.user_id=u.id WHERE a.business_id=? ORDER BY a.created_at DESC LIMIT 100");
        $st->execute([$sess['business_id']]);
        resp(['ok'=>true,'log'=>$st->fetchAll()]);

    // ── GET SETTINGS ──────────────────────────────────
    case 'getSettings':
        $sess = requireAuth();
        $st = db()->prepare("SELECT name, currency FROM businesses WHERE id=?");
        $st->execute([$sess['business_id']]);
        resp(['ok'=>true,'settings'=>$st->fetch()]);

    // ── UPDATE SETTINGS ───────────────────────────────
    case 'updateSettings':
        $sess = requireAuth('owner');
        $db = db();
        $name = trim($body['shopName'] ?? '');
        $cur  = trim($body['currency'] ?? '');
        if ($name) $db->prepare("UPDATE businesses SET name=? WHERE id=?")->execute([$name, $sess['business_id']]);
        if ($cur)  $db->prepare("UPDATE businesses SET currency=? WHERE id=?")->execute([$cur, $sess['business_id']]);
        audit($sess, 'update_settings', "name=$name currency=$cur");
        resp(['ok'=>true]);

    // ── HEARTBEAT / session check ─────────────────────
    case 'ping':
        $sess = requireAuth();
        resp(['ok'=>true,'role'=>$sess['role'],'username'=>$sess['username']]);

    default:
        err('Unknown action', 404);
}
