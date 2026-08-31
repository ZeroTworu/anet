use rand::{Rng, seq::SliceRandom};

pub const CHROME_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
];

pub const FIREFOX_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0",
];

pub const SAFARI_USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
];

pub const CHROME_BRANDS: &[&str] = &[
    "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
    "\"Google Chrome\";v=\"123\", \"Chromium\";v=\"123\", \"Not:A-Brand\";v=\"8\"",
    "\"Chromium\";v=\"124\", \"Google Chrome\";v=\"124\", \"Not-A.Brand\";v=\"99\"",
];

pub const CHROME_PLATFORMS: &[&str] = &["\"Windows\"", "\"Linux\"", "\"macOS\""];

pub const ACCEPT_LANGUAGES: &[&str] = &[
    "ru-RU,ru;q=0.9,en-US;q=0.8,en;q=0.7",
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9,en-US;q=0.8,en;q=0.7",
];

#[derive(Clone, Debug)]
pub struct BrowserProfile {
    pub user_agent: &'static str,
    pub accept_language: &'static str,
    pub chrome_profile: Option<usize>,
}

impl BrowserProfile {
    pub fn random() -> Self {
        let mut rng = rand::thread_rng();
        let family = rng.gen_range(0..3);
        let (user_agent, chrome_profile) = match family {
            0 => {
                let index = rng.gen_range(0..CHROME_USER_AGENTS.len());
                (CHROME_USER_AGENTS[index], Some(index))
            }
            1 => (
                *FIREFOX_USER_AGENTS.choose(&mut rng).unwrap(),
                None,
            ),
            _ => (
                *SAFARI_USER_AGENTS.choose(&mut rng).unwrap(),
                None,
            ),
        };
        Self {
            user_agent,
            accept_language: *ACCEPT_LANGUAGES.choose(&mut rng).unwrap(),
            chrome_profile,
        }
    }

    /// Генерирует HTTP-заголовок, идеально имитирующий браузер
    pub fn build_headers(
        &self,
        method: &str,
        host: &str,
        path: &str,
        content_length: Option<usize>,
        is_chunked: bool,
    ) -> String {
        let mut req = format!(
            "{} {} HTTP/1.1\r\n\
             Host: {}\r\n\
             User-Agent: {}\r\n\
             Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n\
             Accept-Language: {}\r\n\
             Accept-Encoding: gzip, deflate, br\r\n\
             Connection: keep-alive\r\n\
             Sec-Fetch-Dest: document\r\n\
             Sec-Fetch-Mode: navigate\r\n\
             Sec-Fetch-Site: none\r\n\
             Cache-Control: no-cache\r\n\
             Pragma: no-cache\r\n",
            method, path, host, self.user_agent, self.accept_language
        );

        if let Some(index) = self.chrome_profile {
            req.push_str(&format!("sec-ch-ua: {}\r\n", CHROME_BRANDS[index]));
            req.push_str("sec-ch-ua-mobile: ?0\r\n");
            req.push_str(&format!("sec-ch-ua-platform: {}\r\n", CHROME_PLATFORMS[index]));
        }

        if is_chunked {
            req.push_str("Transfer-Encoding: chunked\r\n");
        } else if let Some(len) = content_length {
            req.push_str(&format!("Content-Length: {}\r\n", len));
        }

        req.push_str("\r\n");
        req
    }
}
