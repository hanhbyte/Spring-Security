package com.hanhbyte.springsecurity.student;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/v1/students")
public class StudentController {
    public static final List<Student> STUDENTS = Arrays.asList(
            new Student(1, "Anna Smith"),
            new Student(2, "Maria Jones"),
            new Student(3, "James Bond")
    );

    @GetMapping(path = "{students}")
    public Student getStudent(@PathVariable("studentId")Integer studentId){
        return STUDENTS.stream()
                .filter(student -> studentId.equals(student.getStudentId()))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("student"+studentId+ "does not exists"));
    }


}
