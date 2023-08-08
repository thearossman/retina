#[allow(unused_imports)]
use dns_parser::ResponseCode;
#[allow(unused_imports)]
use crate::protocols::stream::{ConnParser, Session, SessionData};
#[allow(unused_imports)]
use crate::protocols::stream::tls::{parser::TlsParser, *};
#[allow(unused_imports)]
use crate::protocols::stream::http::{parser::HttpParser, *};
#[allow(unused_imports)]
use crate::protocols::stream::dns::{parser::DnsParser, *};


#[derive(Debug)]
pub struct ApplicationData {
    #[cfg(application="tls")]
    pub tls: Option<TlsData>,
    #[cfg(application="dns")]
    pub dns: Option<DnsData>,
    #[cfg(application="http")]
    pub http: Option<HttpData>,
}

#[derive(Debug)]
pub struct TlsData {
    #[cfg(tls="client_hello")]
    pub client_hello: Option<ClientHello>, // TODO break down
    #[cfg(tls="server_hello")]
    pub server_hello: Option<ServerHello>, // TODO break down
    #[cfg(tls="server_certificates")]
    pub server_certificates: Vec<Certificate>,
    #[cfg(tls="client_certificates")]
    pub client_certificates: Vec<Certificate>,
    #[cfg(tls="server_key_exchange")]
    pub server_key_exchange: Option<ServerKeyExchange>,
    #[cfg(tls="client_key_exchange")]
    pub client_key_exchange: Option<ClientKeyExchange>,
}

impl TlsData {
    pub fn new(_tls: Tls) -> Self {
        TlsData {
            #[cfg(tls="client_hello")]
            client_hello: _tls.client_hello,
            #[cfg(tls="server_hello")]
            server_hello: _tls.server_hello,
            #[cfg(tls="server_certificates")]
            server_certificates: _tls.server_certificates,
            #[cfg(tls="client_certificates")]
            client_certificates: _tls.client_certificates,
            #[cfg(tls="server_key_exchange")]
            server_key_exchange: _tls.server_key_exchange,
            #[cfg(tls="client_key_exchange")]
            client_key_exchange: _tls.client_key_exchange,
        }
    }
}

#[derive(Debug)]
pub struct DnsData {
    #[cfg(dns="transaction_id")]
    pub transaction_id: u16,
    #[cfg(dns="dns_query")]
    pub query: Option<DnsQueryData>,
    #[cfg(dns="dns_response")]
    pub response: Option<DnsResponseData>,
}

impl DnsData {
    pub fn new(_dns: Dns) -> Self {
        DnsData {
            #[cfg(dns="transaction_id")]
            transaction_id: _dns.transaction_id,
            #[cfg(dns="dns_query")]
            query: DnsQueryData::get(_dns.query),
            #[cfg(dns="dns_response")]
            response: DnsResponseData::get(_dns.response),
        }
    }
}

#[derive(Debug)]
pub struct DnsQueryData {
    #[cfg(dns_query="num_questions")]
    pub num_questions: u16,
    #[cfg(dns_query="recursion_desired")]
    pub recursion_desired: bool,
    #[cfg(dns_query="queries")]
    pub queries: Vec<String>,
}

impl DnsQueryData {
    pub fn get(_q: Option<DnsQuery>) -> Option<Self> {
        match _q {
            Some(_query) => {
                Some(DnsQueryData {
                    #[cfg(dns_query="num_questions")]
                    num_questions: _query.num_questions,
                    #[cfg(dns_query="recursion_desired")]
                    recursion_desired: _query.recursion_desired,
                    #[cfg(dns_query="queries")]
                    queries: _query.queries,
                })
            }
            None => None
        }
    }
}

#[derive(Debug)]
pub struct DnsResponseData {
    #[cfg(dns_response="response_code")]
    pub response_code: ResponseCode,
    #[cfg(dns_response="authoritative")]
    pub authoritative: bool,
    #[cfg(dns_response="recursion_available")]
    pub recursion_available: bool,
    #[cfg(dns_response="num_answers")]
    pub num_answers: u16,
    #[cfg(dns_response="num_additional")]
    pub num_additional: u16,
    #[cfg(dns_response="num_nameservers")]
    pub num_nameservers: u16,
    #[cfg(dns_response="answers")]
    pub answers: Vec<DnsRecord>,
    #[cfg(dns_response="nameservers")]
    pub nameservers: Vec<DnsRecord>,
    #[cfg(dns_response="additionals")]
    pub additionals: Vec<DnsRecord>,
}

impl DnsResponseData {
    pub fn get(_r: Option<DnsResponse>) -> Option<Self> {
        match _r {
            Some(_response) => {
                Some(DnsResponseData {
                    #[cfg(dns_response="response_code")]
                    response_code: _response.response_code,
                    #[cfg(dns_response="authoritative")]
                    authoritative: _response.authoritative,
                    #[cfg(dns_response="recursion_available")]
                    recursion_available: _response.recursion_available,
                    #[cfg(dns_response="num_answers")]
                    num_answers: _response.num_answers,
                    #[cfg(dns_response="num_additional")]
                    num_additional: _response.num_additional,
                    #[cfg(dns_response="num_nameservers")]
                    num_nameservers: _response.num_nameservers,
                    #[cfg(dns_response="answers")]
                    answers: _response.answers,
                    #[cfg(dns_response="nameservers")]
                    nameservers: _response.nameservers,
                    #[cfg(dns_response="additionals")]
                    additionals: _response.additionals,
                })
            }
            None => None
        }
    }
}

#[derive(Debug)]
pub struct HttpData {
    #[cfg(http="request_data")]
    pub request: HttpRequestData,
    #[cfg(http="response_data")]
    pub response: HttpResponseData,
    #[cfg(http="transaction_depth")]
    pub trans_depth: usize,
}

impl HttpData {
    pub fn new(_http: Http) -> Self {
        HttpData {
            #[cfg(http="request_data")]
            request: HttpRequestData::new(_http.request),
            #[cfg(http="response_data")]
            response: HttpResponseData::new(_http.response),
            #[cfg(http="transaction_depth")]
            trans_depth: _http.trans_depth,
        }
    }
}

#[derive(Debug)]
pub struct HttpRequestData {
    #[cfg(http_request="method")]
    pub method: Option<String>,
    #[cfg(http_request="uri")]
    pub uri: Option<String>,
    #[cfg(http_request="version")]
    pub version: Option<String>,
    #[cfg(http_request="user_agent")]
    pub user_agent: Option<String>,
    #[cfg(http_request="cookie")]
    pub cookie: Option<String>,
    #[cfg(http_request="host")]
    pub host: Option<String>,
    #[cfg(http_request="content_length")]
    pub content_length: Option<usize>,
    #[cfg(http_request="content_type")]
    pub content_type: Option<String>,
    #[cfg(http_request="transfer_encoding")]
    pub transfer_encoding: Option<String>,
}

impl HttpRequestData {
    pub fn new(_request: HttpRequest) -> Self {
        HttpRequestData {
            #[cfg(http_request="method")]
            method: _request.method,
            #[cfg(http_request="uri")]
            uri: _request.uri,
            #[cfg(http_request="version")]
            version: _request.version,
            #[cfg(http_request="user_agent")]
            user_agent: _request.user_agent,
            #[cfg(http_request="cookie")]
            cookie: _request.cookie,
            #[cfg(http_request="host")]
            host: _request.host,
            #[cfg(http_request="content_length")]
            content_length: _request.content_length,
            #[cfg(http_request="content_type")]
            content_type: _request.content_type,
            #[cfg(http_request="transfer_encoding")]
            transfer_encoding: _request.transfer_encoding,
        }
    }
}

#[derive(Debug)]
pub struct HttpResponseData {
    #[cfg(http_response="version")]
    pub version: Option<String>,
    #[cfg(http_response="status_code")]
    pub status_code: Option<u16>,
    #[cfg(http_response="status_msg")]
    pub status_msg: Option<String>,
    #[cfg(http_response="content_length")]
    pub content_length: Option<usize>,
    #[cfg(http_response="content_type")]
    pub content_type: Option<String>,
    #[cfg(http_response="transfer_encoding")]
    pub transfer_encoding: Option<String>,
}

impl HttpResponseData {
    pub fn new(_response: HttpResponse) -> Self {
        HttpResponseData {
            #[cfg(http_response="version")]
            version: _response.version,
            #[cfg(http_response="status_code")]
            status_code: _response.status_code,
            #[cfg(http_response="status_msg")]
            status_msg: _response.status_msg,
            #[cfg(http_response="content_length")]
            content_length: _response.content_length,
            #[cfg(http_response="content_type")]
            content_type: _response.content_type,
            #[cfg(http_response="transfer_encoding")]
            transfer_encoding: _response.transfer_encoding,
        }
    }
}

pub fn custom_parsers() -> Vec<ConnParser> {
    #[allow(unused_mut)]
    let mut ret = vec![];
    ret.push(ConnParser::Dns(DnsParser::default()));
    #[cfg(application="http")]
    ret.push(ConnParser::Http(HttpParser::default()));
    #[cfg(application="tls")]
    ret.push(ConnParser::Tls(TlsParser::default()));
    ret 
}

#[allow(dead_code)]
impl ApplicationData {
    pub fn new() -> Self {
        ApplicationData {
            #[cfg(application="tls")]
            tls: None,
            #[cfg(application="dns")]
            dns: None,
            #[cfg(application="http")]
            http: None,
        }
    }

    #[cfg(application="dns")]
    pub fn add_dns(&mut self, dns: Dns) {
        self.dns = Some(DnsData::new(dns));
    }

    #[cfg(application="http")]
    pub fn add_http(&mut self, http: Http) {
        self.http = Some(HttpData::new(http));
    }

    #[cfg(application="tls")]
    pub fn add_tls(&mut self, tls: Tls) {
        self.tls = Some(TlsData::new(tls));
    }
}

pub(super) struct ApplicationTracker {
    #[allow(dead_code)]
    application_data: ApplicationData,
}

#[allow(dead_code)]
impl ApplicationTracker {

    pub fn new() -> Self {
        ApplicationTracker {
            application_data: ApplicationData::new(),
        }
    }

    pub fn on_match(&mut self, _session: Session)  { 
        #[cfg(application="tls")]
        if let SessionData::Tls(tls) = _session.data {
            self.application_data.add_tls(*tls);
            return;
        }
        #[cfg(application="dns")]
        if let SessionData::Dns(dns) = _session.data {
            self.application_data.add_dns(*dns);
            return;
        }

        #[cfg(application="http")]
        if let SessionData::Http(http) = _session.data {
            self.application_data.add_http(*http);
            return; 
        }
    }

    pub fn to_data(self)  -> Option<ApplicationData> { 
        Some(self.application_data)
    }
}