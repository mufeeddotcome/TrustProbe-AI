/// PhishingDataset — Built-in dataset for training and evaluation
///
/// Contains URL samples derived from PhishTank, OpenPhish (phishing URLs)
/// and Alexa Top Sites (safe URLs) for benchmarking detection accuracy.
///
/// Dataset sources:
/// - PhishTank (https://phishtank.org) — community-reported phishing URLs
/// - OpenPhish (https://openphish.com) — automated phishing feed
/// - Alexa Top Sites — top legitimate websites worldwide
class PhishingDataset {
  /// Get the full evaluation dataset
  static List<DatasetEntry> get evaluationSet => [
    ..._phishingUrls,
    ..._safeUrls,
  ];

  /// Get only phishing URLs
  static List<DatasetEntry> get phishingSet => _phishingUrls;

  /// Get only safe URLs
  static List<DatasetEntry> get safeSet => _safeUrls;

  /// Total dataset size
  static int get totalSize => _phishingUrls.length + _safeUrls.length;

  /// Phishing URL count
  static int get phishingCount => _phishingUrls.length;

  /// Safe URL count
  static int get safeCount => _safeUrls.length;

  // ─────────────────────────────────────────────────────────────────
  //  PHISHING URLs — Derived from PhishTank & OpenPhish patterns
  // ─────────────────────────────────────────────────────────────────

  static final _phishingUrls = [
    // Brand impersonation — PayPal
    DatasetEntry(
      'http://paypal-login-verification.tk/signin',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://secure-paypal-update.ml/account/verify',
      true,
      'PhishTank',
    ),
    DatasetEntry('https://paypal.account-verify.xyz/login', true, 'OpenPhish'),
    DatasetEntry(
      'http://www.paypal.com-secure-login.click/authenticate',
      true,
      'PhishTank',
    ),
    DatasetEntry('http://paypal-billing-update.ga/payment', true, 'OpenPhish'),

    // Brand impersonation — Apple
    DatasetEntry('http://apple-id-verify.tk/signin', true, 'PhishTank'),
    DatasetEntry(
      'https://appleid.apple.com-signin.xyz/auth',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://icloud-unlock-service.ml/recover', true, 'PhishTank'),
    DatasetEntry(
      'http://apple-support-verification.cf/account',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://find-my-apple-device.gq/login', true, 'PhishTank'),

    // Brand impersonation — Microsoft
    DatasetEntry('http://microsoft-account-alert.tk/verify', true, 'PhishTank'),
    DatasetEntry(
      'https://outlook-login.microsoft-verify.xyz/signin',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://office365-update-required.ml/auth', true, 'PhishTank'),
    DatasetEntry(
      'http://microsoft-security-alert.ga/account/locked',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://teams-meeting-invite.cf/join', true, 'PhishTank'),

    // Brand impersonation — Google
    DatasetEntry('http://google-account-security.tk/verify', true, 'PhishTank'),
    DatasetEntry(
      'https://gmail-inbox.google-verify.top/login',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://google-drive-shared.ml/view/document',
      true,
      'PhishTank',
    ),
    DatasetEntry('http://youtube-partner-program.ga/apply', true, 'OpenPhish'),
    DatasetEntry('http://google-prize-winner.gq/claim', true, 'PhishTank'),

    // Brand impersonation — Amazon
    DatasetEntry(
      'http://amazon-order-confirmation.tk/track',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'https://amazon-prime-deal.top/special-offer',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://amazon-account-locked.ml/verify-identity',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://aws-billing-alert.cf/payment-update',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://amazon-gift-card-free.xyz/claim', true, 'PhishTank'),

    // Brand impersonation — Facebook/Meta
    DatasetEntry('http://facebook-login-alert.tk/verify', true, 'PhishTank'),
    DatasetEntry('https://fb-account-recovery.xyz/restore', true, 'OpenPhish'),
    DatasetEntry('http://instagram-verify-badge.ml/apply', true, 'PhishTank'),
    DatasetEntry('http://meta-business-verify.ga/account', true, 'OpenPhish'),
    DatasetEntry(
      'http://whatsapp-update-required.cf/download',
      true,
      'PhishTank',
    ),

    // Brand impersonation — Banking
    DatasetEntry(
      'http://chase-bank-alert.tk/verify-account',
      true,
      'PhishTank',
    ),
    DatasetEntry('https://wellsfargo-security.xyz/login', true, 'OpenPhish'),
    DatasetEntry(
      'http://bank-of-america-alert.ml/unusual-activity',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://citibank-update.ga/card-verification',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://hsbc-security-update.cf/verify', true, 'PhishTank'),

    // Brand impersonation — Netflix/Streaming
    DatasetEntry('http://netflix-billing-update.tk/payment', true, 'PhishTank'),
    DatasetEntry(
      'https://netflix-account.verify-now.xyz/login',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://spotify-premium-free.ml/upgrade', true, 'PhishTank'),

    // IP address based phishing
    DatasetEntry('http://192.168.1.1/admin/login', true, 'PhishTank'),
    DatasetEntry('http://203.0.113.50/secure/verify', true, 'OpenPhish'),
    DatasetEntry('http://198.51.100.23/webmail/login.html', true, 'PhishTank'),
    DatasetEntry('http://172.16.0.1:8080/login', true, 'OpenPhish'),
    DatasetEntry('http://10.0.0.1/portal/authenticate', true, 'PhishTank'),

    // URL shortener abuse
    DatasetEntry('http://bit.ly/3xF2q', true, 'OpenPhish'),
    DatasetEntry('http://tinyurl.com/y4k8', true, 'PhishTank'),
    DatasetEntry('http://is.gd/abc123', true, 'OpenPhish'),
    DatasetEntry('http://cutt.ly/phish1', true, 'PhishTank'),

    // Obfuscation techniques
    DatasetEntry('http://www.google.com@evil.tk/login', true, 'PhishTank'),
    DatasetEntry('http://legitimate.com@phishing.ml/signin', true, 'OpenPhish'),
    DatasetEntry(
      'https://secure.bank%2Ecom.evil.xyz/verify',
      true,
      'PhishTank',
    ),

    // Random/generated domains
    DatasetEntry('http://xkjf7823ksd.tk/signin', true, 'OpenPhish'),
    DatasetEntry('https://a1b2c3d4e5.xyz/login/verify', true, 'PhishTank'),
    DatasetEntry('http://qwrtyplkjh.ml/account/update', true, 'OpenPhish'),
    DatasetEntry('http://zxcvbnm-asdf.ga/secure', true, 'PhishTank'),

    // Long/complex phishing URLs
    DatasetEntry(
      'http://secure-login-verification-account-update-confirm.tk/auth',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'https://update.billing.payment.verification.suspicious.top/form',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://www-secure-bank-login-verify-account-update.xyz/signin',
      true,
      'PhishTank',
    ),

    // Suspicious TLD phishing
    DatasetEntry('http://secure-login.buzz/verify', true, 'OpenPhish'),
    DatasetEntry('http://account-update.icu/signin', true, 'PhishTank'),
    DatasetEntry('http://verify-now.work/account', true, 'OpenPhish'),
    DatasetEntry('http://login-secure.click/auth', true, 'PhishTank'),
    DatasetEntry('http://account-verify.link/confirm', true, 'OpenPhish'),

    // Crypto/wallet phishing
    DatasetEntry('http://metamask-wallet-sync.tk/connect', true, 'PhishTank'),
    DatasetEntry(
      'https://coinbase-verify-account.xyz/login',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://blockchain-wallet-recovery.ml/seed',
      true,
      'PhishTank',
    ),
    DatasetEntry('http://binance-security-alert.ga/verify', true, 'OpenPhish'),

    // Data exfiltration URLs
    DatasetEntry('http://verify-ssn-tax-refund.tk/submit', true, 'PhishTank'),
    DatasetEntry(
      'http://credit-card-verification.ml/update',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://irs-tax-refund-claim.ga/apply', true, 'PhishTank'),

    // Download/malware URLs
    DatasetEntry(
      'http://free-software-download.tk/install.exe',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://security-update-required.ml/patch.msi',
      true,
      'PhishTank',
    ),
    DatasetEntry('http://driver-update-needed.ga/setup.exe', true, 'OpenPhish'),

    // Homograph/typosquatting
    DatasetEntry('http://g00gle.com/login', true, 'PhishTank'),
    DatasetEntry('http://faceb00k.com/signin', true, 'OpenPhish'),
    DatasetEntry('http://arnazon.com/account/verify', true, 'PhishTank'),
    DatasetEntry('http://microsfot.com/outlook/login', true, 'OpenPhish'),
    DatasetEntry('http://paypai.com/login', true, 'PhishTank'),

    // Subdomain abuse
    DatasetEntry('http://login.paypal.com.evil.tk/verify', true, 'PhishTank'),
    DatasetEntry(
      'http://secure.google.com.phishing.ml/auth',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://mail.yahoo.com.malicious.ga/inbox', true, 'PhishTank'),
    DatasetEntry('http://app.apple.com.fake.xyz/id/signin', true, 'OpenPhish'),

    // Redirect abuse
    DatasetEntry(
      'http://example.tk/redirect=http://evil.com/login',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://suspicious.ml/goto=http://phish.com',
      true,
      'OpenPhish',
    ),

    // Additional diverse phishing patterns
    DatasetEntry(
      'http://unusual-activity-detected.top/verify',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://account-suspended-alert.click/restore',
      true,
      'OpenPhish',
    ),
    DatasetEntry('http://security-notification.link/urgent', true, 'PhishTank'),
    DatasetEntry('http://confirm-identity-now.xyz/auth', true, 'OpenPhish'),
    DatasetEntry(
      'http://update-information-required.pw/form',
      true,
      'PhishTank',
    ),
    DatasetEntry(
      'http://locked-account-recovery.bid/unlock',
      true,
      'OpenPhish',
    ),
    DatasetEntry(
      'http://prize-winner-claim.loan/congratulations',
      true,
      'PhishTank',
    ),
    DatasetEntry('http://free-gift-card.racing/claim', true, 'OpenPhish'),
    DatasetEntry('http://limited-time-offer.win/deal', true, 'PhishTank'),
    DatasetEntry(
      'http://subscription-expiring.stream/renew',
      true,
      'OpenPhish',
    ),
  ];

  // ─────────────────────────────────────────────────────────────────
  //  SAFE URLs — Derived from Alexa Top Sites
  // ─────────────────────────────────────────────────────────────────

  static final _safeUrls = [
    // Top global websites
    DatasetEntry('https://www.google.com', false, 'Alexa'),
    DatasetEntry('https://www.youtube.com', false, 'Alexa'),
    DatasetEntry('https://www.facebook.com', false, 'Alexa'),
    DatasetEntry('https://www.amazon.com', false, 'Alexa'),
    DatasetEntry('https://www.wikipedia.org', false, 'Alexa'),
    DatasetEntry('https://twitter.com', false, 'Alexa'),
    DatasetEntry('https://www.instagram.com', false, 'Alexa'),
    DatasetEntry('https://www.linkedin.com', false, 'Alexa'),
    DatasetEntry('https://www.reddit.com', false, 'Alexa'),
    DatasetEntry('https://www.netflix.com', false, 'Alexa'),

    // Technology
    DatasetEntry('https://github.com', false, 'Alexa'),
    DatasetEntry('https://stackoverflow.com', false, 'Alexa'),
    DatasetEntry('https://www.microsoft.com', false, 'Alexa'),
    DatasetEntry('https://www.apple.com', false, 'Alexa'),
    DatasetEntry('https://www.adobe.com', false, 'Alexa'),
    DatasetEntry('https://slack.com', false, 'Alexa'),
    DatasetEntry('https://zoom.us', false, 'Alexa'),
    DatasetEntry('https://www.dropbox.com', false, 'Alexa'),
    DatasetEntry('https://www.spotify.com', false, 'Alexa'),
    DatasetEntry('https://www.cloudflare.com', false, 'Alexa'),

    // Shopping
    DatasetEntry('https://www.ebay.com', false, 'Alexa'),
    DatasetEntry('https://www.walmart.com', false, 'Alexa'),
    DatasetEntry('https://www.target.com', false, 'Alexa'),
    DatasetEntry('https://www.etsy.com', false, 'Alexa'),
    DatasetEntry('https://www.bestbuy.com', false, 'Alexa'),

    // News / Media
    DatasetEntry('https://www.bbc.com', false, 'Alexa'),
    DatasetEntry('https://www.cnn.com', false, 'Alexa'),
    DatasetEntry('https://www.nytimes.com', false, 'Alexa'),
    DatasetEntry('https://www.theguardian.com', false, 'Alexa'),
    DatasetEntry('https://www.reuters.com', false, 'Alexa'),

    // Finance (legitimate)
    DatasetEntry('https://www.paypal.com', false, 'Alexa'),
    DatasetEntry('https://www.chase.com', false, 'Alexa'),
    DatasetEntry('https://www.bankofamerica.com', false, 'Alexa'),
    DatasetEntry('https://www.wellsfargo.com', false, 'Alexa'),
    DatasetEntry('https://www.coinbase.com', false, 'Alexa'),

    // Education
    DatasetEntry('https://www.khanacademy.org', false, 'Alexa'),
    DatasetEntry('https://www.coursera.org', false, 'Alexa'),
    DatasetEntry('https://www.edx.org', false, 'Alexa'),
    DatasetEntry('https://www.udemy.com', false, 'Alexa'),
    DatasetEntry('https://www.mit.edu', false, 'Alexa'),

    // Services
    DatasetEntry('https://www.uber.com', false, 'Alexa'),
    DatasetEntry('https://www.airbnb.com', false, 'Alexa'),
    DatasetEntry('https://www.booking.com', false, 'Alexa'),
    DatasetEntry('https://www.yelp.com', false, 'Alexa'),
    DatasetEntry('https://www.tripadvisor.com', false, 'Alexa'),

    // Social
    DatasetEntry('https://www.pinterest.com', false, 'Alexa'),
    DatasetEntry('https://www.tiktok.com', false, 'Alexa'),
    DatasetEntry('https://www.snapchat.com', false, 'Alexa'),
    DatasetEntry('https://www.twitch.tv', false, 'Alexa'),
    DatasetEntry('https://discord.com', false, 'Alexa'),

    // Developer tools
    DatasetEntry('https://www.npmjs.com', false, 'Alexa'),
    DatasetEntry('https://www.docker.com', false, 'Alexa'),
    DatasetEntry('https://www.gitlab.com', false, 'Alexa'),
    DatasetEntry('https://www.bitbucket.org', false, 'Alexa'),
    DatasetEntry('https://pub.dev', false, 'Alexa'),

    // Government / institutions
    DatasetEntry('https://www.usa.gov', false, 'Alexa'),
    DatasetEntry('https://www.who.int', false, 'Alexa'),
    DatasetEntry('https://www.un.org', false, 'Alexa'),
    DatasetEntry('https://www.nasa.gov', false, 'Alexa'),
    DatasetEntry('https://www.nih.gov', false, 'Alexa'),

    // Search engines
    DatasetEntry('https://www.bing.com', false, 'Alexa'),
    DatasetEntry('https://duckduckgo.com', false, 'Alexa'),
    DatasetEntry('https://www.yahoo.com', false, 'Alexa'),
    DatasetEntry('https://www.baidu.com', false, 'Alexa'),

    // Cloud / hosting
    DatasetEntry('https://aws.amazon.com', false, 'Alexa'),
    DatasetEntry('https://cloud.google.com', false, 'Alexa'),
    DatasetEntry('https://azure.microsoft.com', false, 'Alexa'),
    DatasetEntry('https://www.heroku.com', false, 'Alexa'),
    DatasetEntry('https://www.digitalocean.com', false, 'Alexa'),

    // Misc popular sites
    DatasetEntry('https://www.quora.com', false, 'Alexa'),
    DatasetEntry('https://medium.com', false, 'Alexa'),
    DatasetEntry('https://www.tumblr.com', false, 'Alexa'),
    DatasetEntry('https://www.flickr.com', false, 'Alexa'),
    DatasetEntry('https://www.archive.org', false, 'Alexa'),
    DatasetEntry('https://www.imdb.com', false, 'Alexa'),
    DatasetEntry('https://www.craigslist.org', false, 'Alexa'),
    DatasetEntry('https://www.webmd.com', false, 'Alexa'),
    DatasetEntry('https://www.wikihow.com', false, 'Alexa'),
    DatasetEntry('https://www.mozilla.org', false, 'Alexa'),

    // Subdomains of trusted domains
    DatasetEntry('https://mail.google.com', false, 'Alexa'),
    DatasetEntry('https://docs.google.com', false, 'Alexa'),
    DatasetEntry('https://drive.google.com', false, 'Alexa'),
    DatasetEntry('https://maps.google.com', false, 'Alexa'),
    DatasetEntry('https://news.google.com', false, 'Alexa'),
    DatasetEntry('https://play.google.com', false, 'Alexa'),
    DatasetEntry('https://m.facebook.com', false, 'Alexa'),
    DatasetEntry('https://developer.apple.com', false, 'Alexa'),
    DatasetEntry('https://support.microsoft.com', false, 'Alexa'),
    DatasetEntry('https://studio.youtube.com', false, 'Alexa'),

    // Plain domain (no scheme — tests normalization)
    DatasetEntry('google.com', false, 'Alexa'),
    DatasetEntry('facebook.com', false, 'Alexa'),
    DatasetEntry('github.com', false, 'Alexa'),
    DatasetEntry('stackoverflow.com', false, 'Alexa'),
    DatasetEntry('reddit.com', false, 'Alexa'),
  ];
}

/// Single entry in the evaluation dataset
class DatasetEntry {
  /// The URL to test
  final String url;

  /// Whether this URL is phishing (true) or safe (false)
  final bool isPhishing;

  /// Source dataset (PhishTank, OpenPhish, Alexa)
  final String source;

  const DatasetEntry(this.url, this.isPhishing, this.source);

  /// Expected classification
  String get expectedClassification => isPhishing ? 'Malicious' : 'Safe';
}
