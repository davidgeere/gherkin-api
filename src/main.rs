use std::env;
use std::process::ExitCode;

use gherkin::AppState;

fn main() -> ExitCode {
    load_dotenv();
    let runtime = match tokio::runtime::Runtime::new() {
        Ok(runtime) => runtime,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(1);
        }
    };
    runtime.block_on(run())
}

async fn run() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("serve");
    match command {
        "serve" => {
            if let Err(err) = serve().await {
                eprintln!("{err}");
                return ExitCode::from(1);
            }
        }
        "create-user" => {
            let email = flag(&args, "--email");
            let name = flag(&args, "--name");
            let password = flag(&args, "--password");
            match (email, name, password) {
                (Some(email), Some(name), Some(password)) => {
                    if let Err(err) = create_user(&email, &name, &password).await {
                        eprintln!("{err}");
                        return ExitCode::from(1);
                    }
                }
                _ => {
                    eprintln!("usage: gherkin create-user --email EMAIL --name NAME --password PASSWORD");
                    return ExitCode::from(2);
                }
            }
        }
        "create-token" => {
            let email = flag(&args, "--email");
            let name = flag(&args, "--name");
            match (email, name) {
                (Some(email), Some(name)) => {
                    if let Err(err) = create_token(&email, &name).await {
                        eprintln!("{err}");
                        return ExitCode::from(1);
                    }
                }
                _ => {
                    eprintln!("usage: gherkin create-token --email EMAIL --name NAME");
                    return ExitCode::from(2);
                }
            }
        }
        "help" | "--help" | "-h" => {
            println!(
                "gherkin serve\ngherkin create-user --email EMAIL --name NAME --password PASSWORD\ngherkin create-token --email EMAIL --name NAME"
            );
        }
        other => {
            eprintln!("unknown command {other}");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.windows(2)
        .find(|pair| pair[0] == name)
        .map(|pair| pair[1].clone())
}

fn load_dotenv() {
    let Ok(text) = std::fs::read_to_string(".env") else {
        return;
    };
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if env::var(key).is_err() {
            // SAFETY: called before the runtime starts, from the only thread.
            unsafe { env::set_var(key, value) };
        }
    }
}

fn database_url() -> Result<String, String> {
    env::var("DATABASE_URL").map_err(|_| "DATABASE_URL is not set".to_string())
}

async fn serve() -> Result<(), String> {
    let database_url = database_url()?;
    let setup_token = env::var("GHERKIN_SETUP_TOKEN").unwrap_or_default();
    let bind = env::var("BIND").unwrap_or_else(|_| {
        let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
        if env::var("PORT").is_ok() {
            format!("0.0.0.0:{port}")
        } else {
            format!("127.0.0.1:{port}")
        }
    });
    let state = AppState::connect(&database_url, &setup_token)
        .await
        .map_err(|err| err.to_string())?;
    let listener = tokio::net::TcpListener::bind(&bind)
        .await
        .map_err(|err| err.to_string())?;
    let address = listener.local_addr().map_err(|err| err.to_string())?;
    println!("gherkin listening on {address}");
    axum::serve(listener, gherkin::router(state))
        .await
        .map_err(|err| err.to_string())
}

async fn create_user(email: &str, name: &str, password: &str) -> Result<(), String> {
    let state = AppState::connect(&database_url()?, "")
        .await
        .map_err(|err| err.to_string())?;
    let id = state.create_user_account(email, name, password).await?;
    println!("{id}");
    Ok(())
}

async fn create_token(email: &str, name: &str) -> Result<(), String> {
    let state = AppState::connect(&database_url()?, "")
        .await
        .map_err(|err| err.to_string())?;
    let token = state.create_agent_token(email, name).await?;
    println!("{token}");
    Ok(())
}
