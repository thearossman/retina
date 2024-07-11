use slotmap::{new_key_type, SlotMap};
use regex_automata::hybrid::dfa::{DFA, Cache};
use std::{rc::Rc, cell::RefCell};

new_key_type! { 
    pub(crate) struct CacheKey; 
}

pub(crate) struct CachePool
{ 
    items: SlotMap<CacheKey, Rc<RefCell<Cache>>>,
    free_list: Vec<CacheKey>,
    regex_dfa: DFA,
}

impl CachePool
{

    pub(crate) fn new(regex_dfa: DFA) -> Self {
        CachePool {
            items: SlotMap::with_key(),
            free_list: Vec::new(),
            regex_dfa,
        }
    }

    pub(crate) fn new_cache(&self) -> Rc<RefCell<Cache>> {
        Rc::new(RefCell::new(self.regex_dfa.create_cache()))
    }

    pub(crate) fn get(&mut self) -> (CacheKey, Rc<RefCell<Cache>>)
    { 
        if let Some(key) = self.free_list.pop() {
            (key, self.items.get(key).unwrap().clone())
        } else {
            let key = self.items.insert(self.new_cache());
            (key, self.items.get(key).unwrap().clone())
        }
    }

    pub(crate) fn free(&mut self, cache_key: Option<CacheKey>) {
        if let Some(key) = cache_key {
            if let Some(cache) = self.items.get_mut(key) {
                cache.borrow_mut().reset(&self.regex_dfa);
                self.free_list.push(key);
            }
        }
    }

    pub(crate) fn get_by_key(&mut self, key: CacheKey) -> &mut Rc<RefCell<Cache>> {
        self.items.get_mut(key).unwrap()
    }

}