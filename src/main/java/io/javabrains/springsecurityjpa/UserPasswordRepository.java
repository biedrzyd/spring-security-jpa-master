package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.User;
import io.javabrains.springsecurityjpa.models.UserPasswords;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.Optional;

public interface UserPasswordRepository extends JpaRepository<UserPasswords, Integer> {
    @Query("select password from UserPasswords userpasswords join userpasswords.userid password where userpasswords.userid = :loggedUserId")
    Optional<UserPasswords> getTasksByUserId(@Param("userid") Integer loggedUserId);

}