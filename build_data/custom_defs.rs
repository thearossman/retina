pub mod subscribed {
    pub static FRAME: &'static str = "frame"; 
    pub static CONNECTION: &'static str = "connection";
    pub static APP: &'static str = "application";
}

pub mod frame {
    pub static ZC_FRAME: &'static str = "zc_frame";
    pub static FRAME: &'static str = "frame";
    // Extension: packet features
}

pub mod connection {
    pub static FIVE_TUPLE: &'static str = "five_tuple";
    pub static TIMING: &'static str = "timing";
    pub static HISTORY: &'static str = "history";
    pub static ORIG_FLOW: &'static str = "orig_flow";
    pub static RESP_FLOW: &'static str = "resp_flow";
    // Extension: more connection features
}

pub mod flow {
    pub static NB_PKTS: &'static str = "nb_pkts";
    pub static NB_MALFORMED_PKTS: &'static str = "nb_malformed_pkts";
    pub static NB_LATE_START_PKTS: &'static str = "nb_late_start_pkts";
    pub static NB_BYTES: &'static str = "nb_bytes"; 
    pub static MAX_SIMULT_GAPS: &'static str = "max_simult_gaps"; 
    pub static DATA_START: &'static str = "data_start"; 
    pub static CAPACITY: &'static str = "capacity"; 
    pub static GAPS: &'static str = "gaps"; 
}

pub mod timing {
    pub static TS_FIRST: &'static str = "ts_first";
    pub static TS_TO_SECOND: &'static str = "time_to_second_packet";
    pub static MAX_INACTIVITY: &'static str = "max_inactivity";
    pub static DURATION: &'static str = "duration";
}

pub mod application {
    pub static TLS: &'static str = "tls"; 
    pub static HTTP: &'static str = "http";
    pub static DNS: &'static str = "dns";
}

pub mod tls { 
    pub static CLIENT_HELLO: &'static str = "client_hello";
    pub static SERVER_HELLO: &'static str = "server_hello"; 
    pub static SERVER_CERTS: &'static str = "server_certificates";  
    pub static CLIENT_CERTS: &'static str = "client_certificates"; 
    pub static SERVER_KEY_EXCHANGE: &'static str = "server_key_exchange";
    pub static CLIENT_KEY_EXCHANGE: &'static str = "client_key_exchange";
}

pub mod dns { 
    pub static TXN_ID: &'static str = "transaction_id"; 
    pub static QUERY: &'static str = "dns_query"; 
    pub static RESP: &'static str = "dns_response";
}

pub mod dns_request { 
    pub static NUM_QUESTIONS: &'static str = "num_questions"; 
    pub static RECURSION_DESIRED: &'static str = "recursion_desired"; 
    pub static QUERIES: &'static str = "queries";
}

pub mod dns_response { 
    pub static RESPONSE_CODE: &'static str = "response_code"; 
    pub static AUTHORITATIVE: &'static str = "authoritative"; 
    pub static RECURSION_AVAILABLE: &'static str = "recursion_available";
    pub static NUM_ANSWERS: &'static str = "num_answers";
    pub static NUM_ADDITIONAL: &'static str = "num_additional";
    pub static NUM_NAMESERVERS: &'static str = "num_nameservers";
    pub static ANSWERS: &'static str = "answers";
    pub static NAMESERVERS: &'static str = "nameservers";
    pub static ADDITIONALS: &'static str = "additionals";
}

pub mod http { 
    pub static REQUEST_DATA: &'static str = "request_data"; 
    pub static RESPONSE_DATA: &'static str = "response_data"; 
    pub static TRANSACTION_DEPTH: &'static str = "transaction_depth";
}


pub mod http_request_data {
    pub static METHOD: &'static str = "method"; 
    pub static URI: &'static str = "uri"; 
    pub static VERSION: &'static str = "version"; 
    pub static USER_AGENT: &'static str = "user_agent"; 
    pub static COOKIE: &'static str = "cookie"; 
    pub static HOST: &'static str = "host"; 
    pub static CONTENT_LENGTH: &'static str = "content_length"; 
    pub static CONTENT_TYPE: &'static str = "content_type"; 
    pub static TRANSFER_ENCODING: &'static str = "transfer_encoding"; 
}

pub mod http_response_data {
    pub static VERSION: &'static str = "version"; 
    pub static STATUS_CODE: &'static str = "status_code"; 
    pub static STATUS_MSG: &'static str = "status_msg"; 
    pub static CONTENT_LENGTH: &'static str = "content_length"; 
    pub static CONTENT_TYPE: &'static str = "content_type"; 
    pub static TRANSFER_ENCODING: &'static str = "transfer_encoding"; 
}