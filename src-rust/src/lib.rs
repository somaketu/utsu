use pyo3::prelude::*;
use pyo3::types::PyDict;
use reqwest::blocking::Client;
use scraper::{Html, Selector};
use std::collections::HashSet;
use std::time::Duration;
use url::Url;

#[pyfunction]
fn crawl_url(py: Python, target_url: String, max_depth: u32) -> PyResult<Py<PyDict>> {
    let mut visited = HashSet::new();
    let mut links = HashSet::new();
    let mut scripts = HashSet::new();
    let mut forms = HashSet::new();

    // Configure the client for offensive security: ignore SSL errors, strict timeouts
    let client = Client::builder()
        .timeout(Duration::from_secs(7))
        .danger_accept_invalid_certs(true)
        .build()
        .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(format!("Failed to build client: {}", e)))?;

    let base_url = Url::parse(&target_url)
        .map_err(|e| pyo3::exceptions::PyValueError::new_err(format!("Invalid Target URL: {}", e)))?;
    
    // Queue stores (URL, Depth)
    let mut queue = vec![(base_url.clone(), 0)];

    while let Some((current_url, depth)) = queue.pop() {
        // Stop if we exceed depth or have already visited this exact URL
        if depth > max_depth || !visited.insert(current_url.to_string()) {
            continue;
        }

        // Release the Python GIL while making the network request so the rest of your framework doesn't freeze
        let text = py.allow_threads(|| {
            client.get(current_url.clone()).send().and_then(|res| res.text())
        });

        let html_content = match text {
            Ok(t) => t,
            Err(_) => continue, // Silently drop failed requests to keep the crawler moving
        };

        let document = Html::parse_document(&html_content);
        
        // 1. Extract Links <a href="...">
        if let Ok(a_selector) = Selector::parse("a[href]") {
            for element in document.select(&a_selector) {
                if let Some(href) = element.attr("href") {
                    if let Ok(parsed) = current_url.join(href) {
                        if parsed.scheme() == "http" || parsed.scheme() == "https" {
                            links.insert(parsed.to_string());
                            
                            // Only recurse into internal links
                            if depth < max_depth && parsed.domain() == base_url.domain() {
                                queue.push((parsed, depth + 1));
                            }
                        }
                    }
                }
            }
        }

        // 2. Extract Javascript Files <script src="...">
        if let Ok(script_selector) = Selector::parse("script[src]") {
            for element in document.select(&script_selector) {
                if let Some(src) = element.attr("src") {
                    if let Ok(parsed) = current_url.join(src) {
                        scripts.insert(parsed.to_string());
                    }
                }
            }
        }

        // 3. Extract Form Endpoints <form action="...">
        if let Ok(form_selector) = Selector::parse("form[action]") {
            for element in document.select(&form_selector) {
                if let Some(action) = element.attr("action") {
                    if let Ok(parsed) = current_url.join(action) {
                        forms.insert(parsed.to_string());
                    }
                }
            }
        }
    }

    // Convert Rust HashSets to a Python Dictionary
    let dict = PyDict::new_bound(py);
    dict.set_item("links", links.into_iter().collect::<Vec<String>>())?;
    dict.set_item("scripts", scripts.into_iter().collect::<Vec<String>>())?;
    dict.set_item("forms", forms.into_iter().collect::<Vec<String>>())?;

    Ok(dict.into())
}

#[pymodule]
fn utsu_rust_core(_py: Python, m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(crawl_url, m)?)?;
    Ok(())
}