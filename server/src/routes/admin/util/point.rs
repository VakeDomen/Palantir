use serde::Serialize;

#[derive(Serialize)]
pub struct Point { 
    pub t: String, 
    pub total: i32, 
    pub ai: i32, 
    pub ma100: f32 
}