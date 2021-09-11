package com.hanhbyte.springsecurity.autho;

import java.util.Optional;

public interface ApplicationUserDAO {
     Optional<ApplicationUser> selectApplicationUserByUsername(String username);
}
