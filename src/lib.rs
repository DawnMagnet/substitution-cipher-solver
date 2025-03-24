pub mod ciphey {

    use rust_embed::Embed;

    #[derive(Embed)]
    #[folder = "words/"]
    struct Asset;
    use itertools::Itertools;
    use lazy_static::lazy_static;
    use log::info;
    use regex::Regex;
    use std::collections::{HashMap, HashSet};
    use std::fs::OpenOptions;
    use std::sync::Mutex;
    use std::{fs, io};

    use std::io::{stdin, Read, Write};

    const MAX_GOODNESS_LEVEL: u8 = 2;
    const MAX_BAD_WORDS_RATE: f64 = 0.06;
    const ASCII_LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
    const MAX_WORD_LENGTH_TO_CACHE: usize = 8;

    // Cache for regex patterns
    lazy_static! {
        static ref REGEX_CACHE: Mutex<HashMap<String, Regex>> = Mutex::new(HashMap::new());
    }
    pub fn decrypt(input: &mut Box<dyn Read>, output: &mut Box<dyn Write>) -> io::Result<()> {
        let mut encrypted_text = String::new();
        input.read_to_string(&mut encrypted_text)?;
        encrypted_text = encrypted_text.to_lowercase();

        // Extract words (similar to re.findall(r"[a-z']+", enc_text))
        let re = Regex::new(r"[a-z']+").unwrap();
        let enc_words: Vec<String> = re
            .find_iter(&encrypted_text)
            .map(|m| m.as_str().to_string())
            .filter(|word| !word.contains('\'') && word.len() <= 8)
            .take(200)
            .collect();

        info!(
            "Loaded {} words in encrypted.txt, loading dicts",
            enc_words.len()
        );

        let dict_wordlist = WordList::new();
        info!("Dicts loaded");
        let mut key_finder = KeyFinder::new(enc_words, &dict_wordlist);
        let keys = key_finder.find();

        if keys.is_empty() {
            info!("Key not found, try to increase MAX_BAD_WORDS_RATE");
            return Ok(());
        }

        for (key, bad_words) in keys {
            info!("Possible key: {}, bad words: {}", key, bad_words);
        }

        // Find the best key (with minimum bad words)
        let best_key = keys
            .iter()
            .min_by_key(|&(_, bad_words)| bad_words)
            .map(|(key, bad_words)| (key.clone(), bad_words));

        if let Some((best_key, bad_words)) = best_key {
            info!("Best key: {}, bad_words {}", best_key, bad_words);

            // Create translation map
            let mut translation = HashMap::new();
            for (a, b) in ASCII_LOWERCASE.chars().zip(best_key.chars()) {
                translation.insert(a, b);
            }

            // Decrypt the text
            // let mut encrypted_text = String::new();
            input.read_to_string(&mut encrypted_text)?;
            let decrypted: String = encrypted_text
                .chars()
                .map(|c| {
                    if let Some(&translated) = translation.get(&c) {
                        translated
                    } else {
                        c
                    }
                })
                .collect();

            // Save decrypted text
            output.write_all(decrypted.as_bytes())?;
        }

        Ok(())
    }

    pub fn encrypt(input: &mut Box<dyn Read>, output: &mut Box<dyn Write>) -> io::Result<()> {
        use rand::rng;
        use rand::seq::SliceRandom;

        let mut rng = rng();

        let abc: Vec<char> = ASCII_LOWERCASE.chars().collect();
        let mut key: Vec<char> = abc.clone();
        key.shuffle(&mut rng);

        let mut text = String::new();
        input.read_to_string(&mut text)?;
        text = text.to_lowercase();

        // Create translation map
        let mut translation = HashMap::new();
        for (a, b) in abc.iter().zip(key.iter()) {
            translation.insert(*a, *b);
        }

        // Encrypt the text
        let encrypted: String = text
            .chars()
            .map(|c| *translation.get(&c).unwrap_or(&c))
            .collect();

        output.write_all(encrypted.as_bytes())?;
        // info!("{}", encrypted);

        Ok(())
    }

    pub fn get_input(input: &Option<String>) -> Box<dyn Read> {
        if let Some(input) = input {
            if let Ok(t) = OpenOptions::new().read(true).open(input) {
                // info!("Input file opened: {}", input);
                Box::new(t)
            } else {
                Box::new(stdin())
            }
        } else {
            Box::new(stdin())
        }
    }
    pub fn get_output(output: &Option<String>) -> Box<dyn Write> {
        if let Some(output) = output {
            Box::new(fs::File::create(output).unwrap())
        } else {
            Box::new(io::stdout())
        }
    }

    // Get a compiled regex from cache or create a new one
    fn get_regex(pattern: &str) -> Regex {
        let mut cache = REGEX_CACHE.lock().unwrap();
        if let Some(regex) = cache.get(pattern) {
            regex.clone()
        } else {
            let regex = Regex::new(&format!("^{}$", pattern)).unwrap();
            cache.insert(pattern.to_string(), regex.clone());
            regex
        }
    }

    pub struct WordList {
        words: HashMap<(usize, usize), WordsContainer>,
    }

    enum WordsContainer {
        Cached(HashSet<String>),
        Uncached(Vec<String>),
    }

    impl Default for WordList {
        fn default() -> Self {
            Self::new()
        }
    }

    impl WordList {
        pub fn new() -> WordList {
            let mut words = HashMap::new();

            for goodness in 0..MAX_GOODNESS_LEVEL {
                let path = format!("{}.txt", goodness);
                // let content = fs::read_to_string(&path)
                //     .unwrap_or_else(|_| panic!("Could not read file: {}", path));
                let content = Asset::get(&path).unwrap().data.to_vec();
                let content = String::from_utf8(content).unwrap();

                for word in content.lines() {
                    let word = word.trim();
                    let word_len = word.len();
                    let different_chars = word.chars().collect::<HashSet<char>>().len();
                    let properties = (word_len, different_chars);

                    if word_len > MAX_WORD_LENGTH_TO_CACHE {
                        match words.entry(properties) {
                            std::collections::hash_map::Entry::Vacant(e) => {
                                e.insert(WordsContainer::Uncached(vec![word.to_string()]));
                            }
                            std::collections::hash_map::Entry::Occupied(mut e) => {
                                if let WordsContainer::Uncached(ref mut word_list) = *e.get_mut() {
                                    word_list.push(word.to_string());
                                } else {
                                    panic!("Inconsistent word container type for same properties");
                                }
                            }
                        }
                    } else {
                        let mut word_set = match words.remove(&properties) {
                            Some(WordsContainer::Cached(set)) => set,
                            _ => HashSet::new(),
                        };

                        // Add all possible combinations of the word and dots
                        for i in 0..=word_len {
                            for dots_positions in (0..word_len).combinations(i) {
                                let mut adding_word = word.chars().collect::<Vec<char>>();
                                for &pos in &dots_positions {
                                    adding_word[pos] = '.';
                                }
                                word_set.insert(adding_word.iter().collect::<String>());
                            }
                        }

                        words.insert(properties, WordsContainer::Cached(word_set));
                    }
                }
            }

            WordList { words }
        }

        fn find_word_by_template(&self, template: &str, different_chars: usize) -> bool {
            let properties = (template.len(), different_chars);

            if let Some(words_container) = self.words.get(&properties) {
                match words_container {
                    WordsContainer::Uncached(words) => {
                        let regex = get_regex(template);
                        words.iter().any(|word| regex.is_match(word))
                    }
                    WordsContainer::Cached(words) => words.contains(template),
                }
            } else {
                false
            }
        }
    }

    pub struct KeyFinder<'a> {
        points_threshold: usize,
        dict_wordlist: &'a WordList,
        enc_words: Vec<String>,
        different_chars: HashMap<String, usize>,
        found_keys: HashMap<String, usize>,
    }

    impl<'a> KeyFinder<'a> {
        pub fn new(enc_words: Vec<String>, dict_wordlist: &'a WordList) -> Self {
            let points_threshold = (enc_words.len() as f64 * MAX_BAD_WORDS_RATE) as usize;
            let mut different_chars = HashMap::new();

            for word in &enc_words {
                different_chars.insert(word.clone(), word.chars().collect::<HashSet<char>>().len());
            }

            KeyFinder {
                points_threshold,
                dict_wordlist,
                enc_words,
                different_chars,
                found_keys: HashMap::new(),
            }
        }

        fn get_key_points(&self, key: &str) -> usize {
            let mut translation = HashMap::new();
            for (a, b) in ASCII_LOWERCASE.chars().zip(key.chars()) {
                if b != '.' {
                    translation.insert(a, b);
                }
            }

            let mut points = 0;

            for enc_word in &self.enc_words {
                let different_chars = *self.different_chars.get(enc_word).unwrap();
                let translated_word: String = enc_word
                    .chars()
                    .map(|c| translation.get(&c).map_or('.', |&ch| ch))
                    .collect();

                if !self
                    .dict_wordlist
                    .find_word_by_template(&translated_word, different_chars)
                {
                    points += 1;
                }
            }

            points
        }

        fn recursive_calc_key(
            &mut self,
            key: &str,
            possible_letters: Vec<HashSet<char>>,
            level: usize,
        ) {
            info!("Level: {:3}, key: {}", level, key);

            if !key.contains('.') {
                let points = self.get_key_points(key);
                // info!("Found: {}, bad words: {}", key, points);
                self.found_keys.insert(key.to_string(), points);
                return;
            }

            let mut next_pos = 0;
            let mut min_len = ASCII_LOWERCASE.len() + 1;
            let mut possible_letters = possible_letters;

            for pos in 0..ASCII_LOWERCASE.len() {
                if key.chars().nth(pos) == Some('.') {
                    let letters_to_remove: Vec<char> = possible_letters[pos]
                        .iter()
                        .filter(|&&letter| {
                            let new_key = format!("{}{}{}", &key[..pos], letter, &key[pos + 1..]);
                            self.get_key_points(&new_key) > self.points_threshold
                        })
                        .cloned()
                        .collect();

                    for letter in letters_to_remove {
                        possible_letters[pos].remove(&letter);
                    }

                    if possible_letters[pos].is_empty() {
                        return;
                    }

                    if possible_letters[pos].len() < min_len {
                        min_len = possible_letters[pos].len();
                        next_pos = pos;
                    }
                }
            }

            let letters = possible_letters[next_pos].clone();
            for letter in letters {
                let mut new_possible_letters = possible_letters.clone();

                // Remove this letter from all positions
                for pos in 0..ASCII_LOWERCASE.len() {
                    new_possible_letters[pos].remove(&letter);
                }

                // Set only this letter for the current position
                new_possible_letters[next_pos] = HashSet::from([letter]);

                let new_key = format!("{}{}{}", &key[..next_pos], letter, &key[next_pos + 1..]);

                self.recursive_calc_key(&new_key, new_possible_letters, level + 1);
            }
        }

        pub fn find(&mut self) -> &HashMap<String, usize> {
            if self.found_keys.is_empty() {
                let mut possible_letters = vec![];
                for _ in 0..ASCII_LOWERCASE.len() {
                    let mut chars = HashSet::new();
                    for c in ASCII_LOWERCASE.chars() {
                        chars.insert(c);
                    }
                    possible_letters.push(chars);
                }

                let key = ".".repeat(ASCII_LOWERCASE.len());
                self.recursive_calc_key(&key, possible_letters, 1);
            }

            &self.found_keys
        }
    }
}
