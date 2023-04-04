tonic::include_proto!("voting");

impl From<i32> for Status {
    fn from(code: i32) -> Self {
        Status::new(code)
    }
}

impl Status {
    pub const fn new(code: i32) -> Self {
        Status { code }
    }

    pub const REGISTER_VOTER_SUCCESS: Status = Status::new(0);
    pub const REGISTER_VOTER_EXISTED: Status = Status::new(1);
    pub const REGISTER_VOTER_UNKNOWN: Status = Status::new(2);
    pub const UNREGISTER_VOTER_SUCCESS: Status = Status::new(0);
    pub const UNREGISTER_VOTER_NOTFOUND: Status = Status::new(1);
    pub const UNREGISTER_VOTER_UNKNOWN: Status = Status::new(2);
    pub const CREATE_ELECTION_SUCCESS: Status = Status::new(0);
    pub const CREATE_ELECTION_AUTH: Status = Status::new(1);
    pub const CREATE_ELECTION_INVALID: Status = Status::new(2);
    pub const CREATE_ELECTION_UNKNOWN: Status = Status::new(3);
    pub const CAST_VOTE_SUCCESS: Status = Status::new(0);
    pub const CAST_VOTE_AUTH: Status = Status::new(1);
    pub const CAST_VOTE_INVALID: Status = Status::new(2);
    pub const CAST_VOTE_NOTALLOW: Status = Status::new(3);
    pub const CAST_VOTE_CASTED: Status = Status::new(4);
}

impl ElectionResult {
    pub const ELECTION_RESULT_NOTFOUND: ElectionResult = ElectionResult {
        status: 1,
        counts: Vec::new(),
    };
    pub const ELECTION_RESULT_ONGOING: ElectionResult = ElectionResult {
        status: 2,
        counts: Vec::new(),
    };
}
