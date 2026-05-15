use pest::iterators::Pair;
use pest::Parser;
use pest_derive::Parser;
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use tracing::{debug, error, trace};

#[derive(Parser)]
#[grammar = "client/krb5.pest"]
pub struct KerberosConfigParser;

#[derive(Debug)]
pub enum KerberosConfigError {
    NoConfigFile,
    IoError(std::io::Error),
    ParseError,
}

#[derive(Debug, PartialEq, Default)]
pub struct KerberosConfig {
    pub sections: HashMap<String, Section>,
}

#[derive(Debug, PartialEq, Default)]
pub struct Section {
    pub name: String,
    pub settled: bool,
    pub relations: HashMap<String, Relation>,
}

#[derive(Debug, PartialEq)]
pub struct Relation {
    pub tag: String,
    pub settled: bool,
    pub value: Value,
}

#[derive(Debug, PartialEq)]
pub enum Value {
    // Last value is the latest read
    String(Vec<String>),
    Section(Section),
}

impl KerberosConfig {
    fn subsection(
        relation: &mut Relation,
        pair: Pair<'_, Rule>,
    ) -> Result<(), KerberosConfigError> {
        let section = match &mut relation.value {
            Value::String(_) => return Err(KerberosConfigError::ParseError),
            Value::Section(s) => s,
        };

        for relation_part in pair.into_inner() {
            match relation_part.as_rule() {
                Rule::relation => Self::relation(section, relation_part)?,
                Rule::comment => {}
                Rule::final_mark => {
                    relation.settled = true;
                }
                x => {
                    error!("Unexpected rule {:#?}", x);
                    unreachable!();
                }
            }
        }
        Ok(())
    }

    fn relation(section: &mut Section, pair: Pair<'_, Rule>) -> Result<(), KerberosConfigError> {
        let mut tag = String::new();
        for relation_part in pair.into_inner() {
            match relation_part.as_rule() {
                Rule::tag => {
                    tag = relation_part.as_str().to_string();
                    // If the tag does not exist, insert. If already exists
                    // and is settled ignore this relation completely
                    if section
                        .relations
                        .entry(tag.clone())
                        .or_insert(Relation {
                            tag: tag.clone(),
                            settled: false,
                            value: Value::String(vec![]),
                        })
                        .settled
                    {
                        return Ok(());
                    }
                }
                Rule::final_mark => {
                    section
                        .relations
                        .get_mut(&tag)
                        .ok_or(KerberosConfigError::ParseError)?
                        .settled = true;
                }
                Rule::value => {
                    let v = relation_part.as_str().to_string();
                    match &mut section
                        .relations
                        .get_mut(&tag)
                        .ok_or(KerberosConfigError::ParseError)?
                        .value
                    {
                        Value::String(ref mut items) => items.push(v),
                        Value::Section(_) => return Err(KerberosConfigError::ParseError),
                    };
                }
                Rule::subsection => {
                    // When the relation is created and inserver into section's relation
                    // after initial tag rule match, the value is created as an empty
                    // string vector. Reassign now the value as a subsection
                    let current = section
                        .relations
                        .get_mut(&tag)
                        .ok_or(KerberosConfigError::ParseError)?;

                    match &current.value {
                        Value::String(items) => {
                            if !items.is_empty() {
                                return Err(KerberosConfigError::ParseError);
                            }
                            current.value = Value::Section(Section {
                                name: tag.clone(),
                                settled: current.settled,
                                relations: HashMap::new(),
                            });
                        }
                        Value::Section(_) => {}
                    };

                    Self::subsection(
                        section
                            .relations
                            .get_mut(&tag)
                            .ok_or(KerberosConfigError::ParseError)?,
                        relation_part,
                    )?
                }
                x => {
                    error!("Unexpected rule {:#?}", x);
                    unreachable!();
                }
            }
        }
        Ok(())
    }

    fn section(
        config: &mut KerberosConfig,
        pair: Pair<'_, Rule>,
    ) -> Result<(), KerberosConfigError> {
        let mut name = String::new();
        for section_part in pair.into_inner() {
            match section_part.as_rule() {
                Rule::section_name => {
                    name = section_part.as_str().to_string();
                    // If the section does not exist, insert. If already exists
                    // and is settled return and ignore this section completely
                    if config
                        .sections
                        .entry(name.clone())
                        .or_insert(Section {
                            name: name.clone(),
                            settled: false,
                            relations: HashMap::new(),
                        })
                        .settled
                    {
                        return Ok(());
                    }
                }
                Rule::relation => Self::relation(
                    config
                        .sections
                        .get_mut(&name)
                        .ok_or(KerberosConfigError::ParseError)?,
                    section_part,
                )?,
                Rule::final_mark => {
                    config
                        .sections
                        .get_mut(&name)
                        .ok_or(KerberosConfigError::ParseError)?
                        .settled = true;
                }
                Rule::comment => {}
                x => {
                    error!("Unexpected rule {:#?}", x);
                    unreachable!();
                }
            }
        }
        Ok(())
    }

    /// Parse the content of a `krb5.conf` file from a &str
    pub fn parse(input: &str, config: &mut KerberosConfig) -> Result<(), KerberosConfigError> {
        let parsed = KerberosConfigParser::parse(Rule::file, input)
            .map_err(|_| KerberosConfigError::ParseError)?
            .next()
            .ok_or(KerberosConfigError::ParseError)?;

        for file_part in parsed.into_inner() {
            match file_part.as_rule() {
                Rule::section => Self::section(config, file_part),
                Rule::include_file => {
                    let mut include_parts = file_part.into_inner();
                    let path = include_parts
                        .next()
                        .ok_or(KerberosConfigError::ParseError)?
                        .as_str()
                        .to_string();
                    let path = PathBuf::from(path);
                    Self::include_file(&path, config)
                }
                Rule::include_dir => {
                    let mut include_parts = file_part.into_inner();
                    let path = include_parts
                        .next()
                        .ok_or(KerberosConfigError::ParseError)?
                        .as_str()
                        .to_string();
                    let path = PathBuf::from(path);
                    Self::include_dir(&path, config)
                }
                Rule::EOI => Ok(()),
                Rule::comment => Ok(()),
                x => {
                    error!("Unexpected rule {:#?}", x);
                    unreachable!();
                }
            }?
        }
        Ok(())
    }

    fn include_file(
        path: &PathBuf,
        config: &mut KerberosConfig,
    ) -> Result<(), KerberosConfigError> {
        let unparsed = fs::read_to_string(path.as_path()).map_err(|e| {
            debug!("Failed to read file {path:?}: {e}");
            KerberosConfigError::IoError(e)
        })?;
        Self::parse(&unparsed, config)
    }
    fn include_dir(path: &PathBuf, config: &mut KerberosConfig) -> Result<(), KerberosConfigError> {
        let mut files: Vec<PathBuf> = fs::read_dir(path)
            .map_err(|e| {
                error!("Failed to read directory {path:?}: {e}");
                KerberosConfigError::IoError(e)
            })?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                let file_name = path.file_name().and_then(|f| f.to_str()).unwrap_or("");
                // Only include files with alphanumeric names, dashes, or underscores
                let valid_name = file_name
                    .chars()
                    .all(|c| c.is_alphanumeric() || c == '-' || c == '_');
                // Also include ".conf" files, as long as they do not start with '.'
                valid_name || (file_name.ends_with(".conf") && !file_name.starts_with('.'))
            })
            .collect();

        // Process files in alphanumeric order
        files.sort();

        for file in files {
            Self::include_file(&file, config)?;
        }
        Ok(())
    }

    fn from_usr_etc() -> Result<KerberosConfig, KerberosConfigError> {
        let mut config = KerberosConfig::default();

        // TODO To build time option
        let user_cfg_path = PathBuf::from("/etc/krb5.conf");
        if user_cfg_path.exists() {
            trace!(?user_cfg_path, "Load user config");
            let unparsed = fs::read_to_string(&user_cfg_path).map_err(|e| {
                error!("Failed to read file {user_cfg_path:?}: {e}");
                KerberosConfigError::IoError(e)
            })?;
            Self::parse(&unparsed, &mut config)?;
        } else {
            let distro_cfg_path = PathBuf::from("/usr/etc/krb5.conf");
            if distro_cfg_path.exists() {
                trace!(?distro_cfg_path, "Load distro config");
                let unparsed = fs::read_to_string(&distro_cfg_path).map_err(|e| {
                    error!("Failed to read file {distro_cfg_path:?}: {e}");
                    KerberosConfigError::IoError(e)
                })?;
                Self::parse(&unparsed, &mut config)?;
            } else {
                return Err(KerberosConfigError::NoConfigFile);
            }
        }

        Ok(config)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<KerberosConfig, KerberosConfigError> {
        let unparsed = fs::read_to_string(path).map_err(|e| {
            debug!("Failed to read file: {e}");
            KerberosConfigError::IoError(e)
        })?;
        let mut config = KerberosConfig::default();
        Self::parse(&unparsed, &mut config)?;
        Ok(config)
    }

    pub fn from_defaults() -> Result<KerberosConfig, KerberosConfigError> {
        let path = match env::var("KRB5_CONFIG") {
            Ok(v) => PathBuf::from(v),
            Err(_) => return Self::from_usr_etc(),
        };
        let unparsed = fs::read_to_string(path.as_path()).map_err(|e| {
            debug!("Failed to read file {path:?}: {e}");
            KerberosConfigError::IoError(e)
        })?;
        let mut config = KerberosConfig::default();
        Self::parse(&unparsed, &mut config)?;
        Ok(config)
    }

    pub fn libdefaults(&self, tag: &str) -> Option<String> {
        self.sections
            .get("libdefaults")
            .and_then(|s| s.relations.get(tag))
            .map(|r| match &r.value {
                Value::String(v) => v.last().cloned(),
                Value::Section(_) => None,
            })?
    }

    pub fn realms(&self, realm: &str, tag: &str) -> Option<String> {
        self.sections
            .get("realms")
            .and_then(|s| s.relations.get(realm))
            .map(|r| match &r.value {
                Value::String(_) => None,
                Value::Section(r) => r.relations.get(tag).and_then(|r| match &r.value {
                    Value::String(v) => v.last().cloned(),
                    Value::Section(_) => None,
                }),
            })?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;
    use tempfile::NamedTempFile;

    #[test]
    fn test_config_basic_section_parsing() {
        let input = r#"
            # abar
            [libdefaults]*
            default_realm = EXAMPLE.COM
            ticket_lifetime* = 24h
            ticket_lifetime = 1h

            [libdefaults]
            default_realm = IGNORED.COM

            [realms]
            # afoo
            ONE.EXAMPLE.COM = {
                kdc = 192.168.1.1
            }*
            ONE.EXAMPLE.COM = {
                kdc = 192.168.1.2
            }
            TWO.EXAMPLE.COM* = {
                kdc = 192.168.1.1
            }
            TWO.EXAMPLE.COM* = {
                kdc = 192.168.1.2
            }
        "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_ok());

        assert!(config.sections.contains_key("libdefaults"));

        let libdefaults = &config.sections["libdefaults"];
        assert!(libdefaults.settled);
        assert_eq!(
            libdefaults.relations.get("default_realm"),
            Some(&Relation {
                tag: "default_realm".to_string(),
                settled: false,
                value: Value::String(vec!["EXAMPLE.COM".to_string()]),
            })
        );

        assert_eq!(
            libdefaults.relations.get("ticket_lifetime"),
            Some(&Relation {
                tag: "ticket_lifetime".to_string(),
                settled: true,
                value: Value::String(vec!["24h".to_string()]),
            })
        );

        let realms = &config.sections["realms"];
        let one = &realms.relations["ONE.EXAMPLE.COM"];
        assert_eq!(one.tag, "ONE.EXAMPLE.COM".to_string());
        assert!(one.settled);
        match &one.value {
            Value::Section(s) => {
                assert_eq!(s.name, "ONE.EXAMPLE.COM".to_string());
                //assert!(s.settled);
                let kdc = &s.relations["kdc"];
                assert_eq!(kdc.tag, "kdc".to_string());
                assert_eq!(kdc.value, Value::String(vec!["192.168.1.1".to_string()]));
            }
            _ => panic!(),
        }

        let two = &realms.relations["TWO.EXAMPLE.COM"];
        assert_eq!(two.tag, "TWO.EXAMPLE.COM".to_string());
        assert!(two.settled);
        match &two.value {
            Value::Section(s) => {
                assert_eq!(s.name, "TWO.EXAMPLE.COM".to_string());
                //assert!(s.settled);
                let kdc = &s.relations["kdc"];
                assert_eq!(kdc.tag, "kdc".to_string());
                assert_eq!(kdc.value, Value::String(vec!["192.168.1.1".to_string()]));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn test_config_non_closed_nested_section() {
        // Test non-closed subsections
        let input = r#"
            [realms]
                EXAMPLE.COM = {
                    kdc = kerberos.example.com
                    admin_server = admin.example.com
            "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_nested_section() {
        let input = r#"
                [realms]
                    EXAMPLE.COM = {
                        kdc = kerberos.example.com
                        admin_server = admin.example.com
                    }
                "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_ok());

        assert!(config.sections.contains_key("realms"));

        let realms = &config.sections["realms"];
        let realm_entry = &realms.relations["EXAMPLE.COM"];

        if let Value::Section(nested_section) = &realm_entry.value {
            assert_eq!(
                &nested_section.relations["kdc"],
                &Relation {
                    tag: "kdc".to_string(),
                    settled: false,
                    value: Value::String(vec!["kerberos.example.com".to_string()])
                }
            );
            assert_eq!(
                &nested_section.relations["admin_server"],
                &Relation {
                    tag: "admin_server".to_string(),
                    settled: false,
                    value: Value::String(vec!["admin.example.com".to_string()])
                }
            );
        } else {
            panic!("Expected nested section, but got something else");
        }

        // Test nested recursion
        let input = r#"
              [appdefaults]
                  telnet = {
                      ATHENA.MIT.EDU = {
                          option1 = false
                      }
                  }
                  telnet = {
                      option1 = true
                      option2 = true
                  }
                  ATHENA.MIT.EDU = {
                      option2 = false
                  }
                  option2 = true
            "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_ok());

        // From krb5.conf manpage:
        //
        // if telnet is running in the realm EXAMPLE.COM, it should, by default, have option1 and option2 set to true.
        // However, a telnet program in the realm ATHENA.MIT.EDU should have option1 set to false and option2 set to
        // true. Any other programs in ATHENA.MIT.EDU should have option2 set to false by default.  Any programs
        // running in other realms should have option2 set to true.

        let appdefaults = &config.sections["appdefaults"];

        if let Value::Section(telnet) = &appdefaults.relations["telnet"].value {
            assert_eq!(telnet.relations.len(), 3);

            assert_eq!(
                &telnet.relations["option1"],
                &Relation {
                    tag: "option1".to_string(),
                    settled: false,
                    value: Value::String(vec!["true".to_string()])
                }
            );
            assert_eq!(
                &telnet.relations["option2"],
                &Relation {
                    tag: "option2".to_string(),
                    settled: false,
                    value: Value::String(vec!["true".to_string()])
                }
            );

            if let Value::Section(athena) = &telnet.relations["ATHENA.MIT.EDU"].value {
                assert_eq!(athena.relations.len(), 1);
                assert_eq!(
                    &athena.relations["option1"],
                    &Relation {
                        tag: "option1".to_string(),
                        settled: false,
                        value: Value::String(vec!["false".to_string()])
                    }
                );
            }
        } else {
            panic!();
        }

        if let Value::Section(athena) = &appdefaults.relations["ATHENA.MIT.EDU"].value {
            // ATHENA.MIT.EDU options for all apps
            assert_eq!(athena.relations.len(), 1);
            assert_eq!(
                &athena.relations["option2"],
                &Relation {
                    tag: "option2".to_string(),
                    settled: false,
                    value: Value::String(vec!["false".to_string()])
                }
            );
        } else {
            panic!()
        }

        assert_eq!(
            &appdefaults.relations["option2"],
            &Relation {
                tag: "option2".to_string(),
                settled: false,
                value: Value::String(vec!["true".to_string()])
            }
        );
    }

    #[test]
    fn test_config_comments_and_whitespace() {
        let input = r#"
            # This is a comment
            [libdefaults]
            default_realm = EXAMPLE.COM
    
            ; Another comment format
              ; This time with leading spaces
               # in both formats
            ticket_lifetime = 24h
        "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_ok());

        assert!(config.sections.contains_key("libdefaults"));

        let libdefaults = &config.sections["libdefaults"];
        assert_eq!(libdefaults.relations.len(), 2);
        assert_eq!(
            &libdefaults.relations["default_realm"].value,
            &Value::String(vec!["EXAMPLE.COM".to_string()])
        );
        assert_eq!(
            &libdefaults.relations["ticket_lifetime"].value,
            &Value::String(vec!["24h".to_string()])
        );
    }

    #[test]
    fn test_config_invalid_line() {
        let input = r#"
            [libdefaults]
            # Missing '='
            default_realm EXAMPLE.COM
        "#;

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_empty_config() {
        let input = "";

        let mut config = KerberosConfig::default();
        let result = KerberosConfig::parse(input, &mut config);
        assert!(result.is_ok());
    }

    #[test]
    fn test_config_from_file_success() {
        let file_content = r#"
            [domain_realm]
            .example.com = EXAMPLE.COM
            .otherdomain.com = OTHERREALM.COM
        "#;

        // Write test content to a temporary file
        let mut file = NamedTempFile::new().expect("new namedtempfile");
        file.write_all(file_content.as_bytes())
            .expect("Failed to write to temporary file");
        file.flush().expect("flush temp file");

        // Test from_file
        let result = KerberosConfig::from_file(file.path());
        assert!(result.is_ok());

        let config = result.unwrap();
        assert!(config.sections.contains_key("domain_realm"));

        let domain_realm = &config.sections["domain_realm"];
        assert_eq!(
            &domain_realm.relations[".example.com"].value,
            &Value::String(vec!["EXAMPLE.COM".to_string()])
        );
        assert_eq!(
            &domain_realm.relations[".otherdomain.com"].value,
            &Value::String(vec!["OTHERREALM.COM".to_string()])
        );

        // Clean up temporary file
        file.close().expect("close temp file");
    }

    #[test]
    fn test_config_from_file_failure() {
        let invalid_path = std::path::Path::new("non_existent.conf");
        let result = KerberosConfig::from_file(invalid_path);
        assert!(result.is_err());
    }

    #[test]
    fn test_config_parse_include() {
        let content = r#"
            [libdefaults]
            default_realm = FROM.INCLUDED.CONF
        "#;
        let mut inc_file = NamedTempFile::new().expect("new namedtempfile");
        inc_file
            .write_all(content.as_bytes())
            .expect("Failed to write to temporary file");
        inc_file.flush().expect("flush temp file");

        let content = r#"
            [libdefaults]
            default_realm = FROM.MAIN.CONF
        "#;

        // Fist include, then main
        let content = format!("include {}\n{}", inc_file.path().to_string_lossy(), content);
        let mut main_file = NamedTempFile::new().expect("new namedtempfile");
        main_file
            .write_all(content.as_bytes())
            .expect("Failed to write to temporary file");
        main_file.flush().expect("flush temp file");

        let config = KerberosConfig::from_file(main_file.path()).expect("parse");

        let libdefaults = &config.sections["libdefaults"];
        assert_eq!(
            &libdefaults.relations["default_realm"].value,
            &Value::String(vec![
                "FROM.INCLUDED.CONF".to_string(),
                "FROM.MAIN.CONF".to_string(),
            ])
        );

        main_file.close().expect("close");

        // Fist main, then include
        let content = r#"
            [libdefaults]
            default_realm = FROM.MAIN.CONF
        "#;
        let content = format!("{}\ninclude {}", content, inc_file.path().to_string_lossy());
        let mut main_file = NamedTempFile::new().expect("new namedtempfile");
        main_file
            .write_all(content.as_bytes())
            .expect("Failed to write to temporary file");
        main_file.flush().expect("flush temp file");

        let config = KerberosConfig::from_file(main_file.path()).expect("parse");

        let libdefaults = &config.sections["libdefaults"];
        assert_eq!(
            &libdefaults.relations["default_realm"].value,
            &Value::String(vec![
                "FROM.MAIN.CONF".to_string(),
                "FROM.INCLUDED.CONF".to_string(),
            ])
        );

        main_file.close().expect("close");

        inc_file.close().expect("close");
    }

    #[test]
    fn test_config_parse_includedir() {
        let inc_dir = tempdir().expect("tempdir");

        let inc_a_content = r#"
            [libdefaults]
            default_realm = FROM.INC.A.CONF
        "#;

        let inc_b_content = r#"
            [libdefaults]
            default_realm = FROM.INC.B.CONF
        "#;

        let inc_a_path = inc_dir.path().join("a.conf");
        let mut inc_a_file = File::create(inc_a_path).expect("create");
        inc_a_file
            .write_all(inc_a_content.as_bytes())
            .expect("Failed to write to temporary file");
        inc_a_file.flush().expect("flush temp file");

        let inc_b_path = inc_dir.path().join("b.conf");
        let mut inc_b_file = File::create(inc_b_path).expect("create");
        inc_b_file
            .write_all(inc_b_content.as_bytes())
            .expect("Failed to write to temporary file");
        inc_b_file.flush().expect("flush temp file");

        let main_content = format!(
            "
            includedir {}
            [libdefaults]
            default_realm = FROM.MAIN.CONF
        ",
            inc_dir.path().to_string_lossy()
        );
        let mut main_file = NamedTempFile::new().expect("new namedtempfile");
        main_file
            .write_all(main_content.as_bytes())
            .expect("Failed to write to temporary file");
        main_file.flush().expect("flush temp file");

        let config = KerberosConfig::from_file(main_file.path()).expect("parse");

        let libdefaults = &config.sections["libdefaults"];
        assert_eq!(
            &libdefaults.relations["default_realm"].value,
            &Value::String(vec![
                "FROM.INC.A.CONF".to_string(),
                "FROM.INC.B.CONF".to_string(),
                "FROM.MAIN.CONF".to_string()
            ])
        );

        drop(inc_a_file);
        drop(inc_b_file);
        inc_dir.close().expect("close");
        main_file.close().expect("close");
    }
}
