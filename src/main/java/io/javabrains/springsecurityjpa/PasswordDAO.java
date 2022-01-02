package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.Password;
import io.javabrains.springsecurityjpa.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface PasswordDAO extends JpaRepository<Password, Integer> {

}