// tamanegi - lib.rs
// Quick and dirty parser for GitLeaks scan tool report
//

use nom::{
    branch::alt,
    bytes::complete::{tag, take_till},
    character::complete::{char, digit1, line_ending},
    combinator::{map_res, opt, recognize},
    multi::many0,
    sequence::{pair, preceded, terminated},
    IResult,
};

use std::convert::Infallible;
use std::str::FromStr;

#[derive(Debug, PartialEq)]
pub struct Finding {
    pub secret_token: Option<String>,
    pub secret: Option<String>,
    pub rule_id: Option<String>,
    pub entropy: Option<f64>,
    pub file: Option<String>,
    pub line: Option<u32>,
    pub commit: Option<String>,
    pub author: Option<String>,
    pub email: Option<String>,
    pub date: Option<String>,
    pub fingerprint: Option<String>,
}

fn parse_line<'a>(prefix: &'static str) -> impl FnMut(&'a str) -> IResult<&'a str, Option<String>> {
    preceded(
        tag(prefix),
        opt(map_res(take_till(|c| c == '\n'), |s: &str| {
            Ok::<_, Infallible>(s.trim().to_string())
        })),
    )
}

fn parse_f64(input: &str) -> IResult<&str, Option<f64>> {
    opt(map_res(
        recognize(pair(
            opt(alt((char('-'), char('+')))),
            pair(digit1, opt(pair(char('.'), digit1))),
        )),
        |s: &str| f64::from_str(s),
    ))(input)
}

fn parse_u32<'a>(input: &'a str) -> IResult<&'a str, Option<u32>> {
    opt(map_res(digit1, |s: &str| s.parse::<u32>()))(input)
}

pub fn parse_finding(input: &str) -> IResult<&str, Finding> {
    let (input, secret_token) = parse_line("Finding: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, secret) = parse_line("Secret: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, rule_id) = parse_line("RuleID: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, entropy) = preceded(tag("Entropy: "), parse_f64)(input)?;
    let (input, _) = line_ending(input)?;
    let (input, file) = parse_line("File: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, line) = preceded(tag("Line: "), parse_u32)(input)?;
    let (input, _) = line_ending(input)?;
    let (input, commit) = parse_line("Commit: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, author) = parse_line("Author: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, email) = parse_line("Email: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, date) = parse_line("Date: ")(input)?;
    let (input, _) = line_ending(input)?;
    let (input, fingerprint) = parse_line("Fingerprint: ")(input)?;
    let (input, _) = opt(line_ending)(input)?;

    Ok((
        input,
        Finding {
            secret_token,
            secret,
            rule_id,
            entropy,
            file,
            line,
            commit,
            author,
            email,
            date,
            fingerprint,
        },
    ))
}

pub fn parse_findings(input: &str) -> IResult<&str, Vec<Finding>> {
    many0(terminated(parse_finding, opt(line_ending)))(input)
}
