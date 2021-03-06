package io.javabrains.springsecurityjpa;

import io.javabrains.springsecurityjpa.models.LoginHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginDAO extends JpaRepository<LoginHistory, Integer> {

}