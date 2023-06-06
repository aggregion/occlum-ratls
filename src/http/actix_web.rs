use std::net;

use actix_http::{body::MessageBody, Request};
use actix_service::{IntoServiceFactory, ServiceFactory};
use actix_web::dev::{AppConfig, Response};
use actix_web::*;
use rustls::ServerConfig;

use crate::{config::RaTlsConfig, RaTlsConfigBuilder};

pub trait ActixWebWithRatls<F, I, S, B>
where
    F: Fn() -> I + Send + Clone + 'static,
    I: IntoServiceFactory<S, Request>,
    S: ServiceFactory<Request, Config = AppConfig>,
    S::Error: Into<Error>,
    S::InitError: std::fmt::Debug,
    S::Response: Into<Response<B>>,
    B: MessageBody,
{
    fn bind_ratls<A: net::ToSocketAddrs>(
        self,
        addr: A,
        config: RaTlsConfig,
    ) -> Result<HttpServer<F, I, S, B>, std::io::Error>;
}

impl<F, I, S, B> ActixWebWithRatls<F, I, S, B> for HttpServer<F, I, S, B>
where
    F: Fn() -> I + Send + Clone + 'static,
    I: IntoServiceFactory<S, Request>,
    S: ServiceFactory<Request, Config = AppConfig> + 'static,
    S::Error: Into<Error>,
    S::InitError: std::fmt::Debug,
    S::Response: Into<Response<B>>,
    B: MessageBody + 'static,
{
    fn bind_ratls<A: net::ToSocketAddrs>(
        self,
        addr: A,
        config: RaTlsConfig,
    ) -> Result<Self, std::io::Error> {
        self.bind_rustls(addr, ServerConfig::from_ratls_config(config))
    }
}
