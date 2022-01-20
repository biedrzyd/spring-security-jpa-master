package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.Password;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface PasswordDAO extends JpaRepository<Password, Integer> {

}