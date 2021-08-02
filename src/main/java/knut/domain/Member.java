package knut.domain;

import com.sun.istack.NotNull;
import lombok.*;

import javax.persistence.*;
import java.util.Set;

@Entity
@Getter
@Setter
@Builder
@AllArgsConstructor
@NoArgsConstructor
public class Member {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "member_id", unique = true)
    private Long id;

    @NotNull
    @Column(length = 20)
    private String name;

    @NotNull
    @Column(length = 30)
    private String password;

    private boolean activated;

    @ManyToMany
    @JoinTable(
            name = "AUTHORITY",
            joinColumns = {@JoinColumn(name = "member_id", referencedColumnName = "member_id")},
            inverseJoinColumns = {@JoinColumn(name = "authority_name", referencedColumnName = "authority_name")})
    private Set<Authority> authorities;
    // 중복이 없어야 하기 때문에 SET
}
