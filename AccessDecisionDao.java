package bc.escaperoom.dao;

import bc.escaperoom.model.AccessDecisionRequest;
import bc.escaperoom.model.AccessDecisionResponse;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.LocalDateTime;

public class AccessDecisionDao {
    private final Connection connection;

    public AccessDecisionDao(Connection connection) {
        this.connection = connection;
    }

    public AccessDecisionResponse authorize(AccessDecisionRequest request) throws SQLException {
        AccessTarget target = findTarget(request.accessPointId());
        if (target == null) {
            return denied(request, null, "Access point does not exist.");
        }

        Integer permissionId = findMatchingPermission(
                request.badgeId(), target, request.accessTime());

        if (permissionId == null) {
            return denied(request, target.accessPointCode(),
                    "No matching permission record was found.");
        }

        return new AccessDecisionResponse(
                request.badgeId(),
                request.accessPointId(),
                target.accessPointCode(),
                request.accessTime(),
                true,
                "GRANTED",
                permissionId,
                "A matching " + target.scopeType() + " permission record was found."
        );
    }

    private AccessTarget findTarget(int accessPointId) throws SQLException {
        String sql = """
                SELECT ap.access_point_code, ap.access_point_type,
                       ap.building_id, ap.floor_id, ap.room_id,
                       COALESCE(r.requires_explicit_permission, FALSE) AS requires_explicit_permission
                FROM access_point ap
                LEFT JOIN room r ON r.room_id = ap.room_id
                WHERE ap.access_point_id = ?
                """;
        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setInt(1, accessPointId);
            try (ResultSet resultSet = statement.executeQuery()) {
                if (!resultSet.next()) {
                    return null;
                }
                String accessPointType = resultSet.getString("access_point_type");
                if ("ROOM_DOOR".equals(accessPointType)
                        && resultSet.getBoolean("requires_explicit_permission")) {
                    return new AccessTarget(
                            resultSet.getString("access_point_code"),
                            "ROOM",
                            resultSet.getInt("room_id")
                    );
                }
                if ("FLOOR_GATE".equals(accessPointType)
                        || "ELEVATOR_PANEL".equals(accessPointType)) {
                    return new AccessTarget(
                            resultSet.getString("access_point_code"),
                            "FLOOR",
                            resultSet.getInt("floor_id")
                    );
                }
                return new AccessTarget(
                        resultSet.getString("access_point_code"),
                        "BUILDING",
                        resultSet.getInt("building_id")
                );
            }
        }
    }

    private Integer findMatchingPermission(
            String badgeId,
            AccessTarget target,
            LocalDateTime accessTime
    ) throws SQLException {
        String targetColumn = switch (target.scopeType()) {
            case "BUILDING" -> "building_id";
            case "FLOOR" -> "floor_id";
            case "ROOM" -> "room_id";
            default -> throw new IllegalArgumentException("Unsupported scope type");
        };

        String sql = "SELECT bp.permission_id "
                + "FROM badge_permission bp "
                + "JOIN badge b ON b.badge_id = bp.badge_id "
                + "WHERE bp.badge_id = ? "
                + "AND bp.scope_type = ? "
                + "AND bp." + targetColumn + " = ? "
                + "AND b.badge_status = 'ACTIVE' "
                + "AND b.issued_at <= ? "
                + "AND (b.expires_at IS NULL OR ? < b.expires_at) "
                + "AND bp.permission_status = 'ACTIVE' "
                + "AND bp.valid_from <= ? "
                + "AND (bp.valid_until IS NULL OR ? < bp.valid_until) "
                + "ORDER BY bp.valid_from DESC, bp.permission_id DESC "
                + "LIMIT 1";

        try (PreparedStatement statement = connection.prepareStatement(sql)) {
            statement.setString(1, badgeId);
            statement.setString(2, target.scopeType());
            statement.setInt(3, target.targetId());
            statement.setObject(4, accessTime);
            statement.setObject(5, accessTime);
            statement.setObject(6, accessTime);
            statement.setObject(7, accessTime);
            try (ResultSet resultSet = statement.executeQuery()) {
                return resultSet.next() ? resultSet.getInt("permission_id") : null;
            }
        }
    }

    private AccessDecisionResponse denied(
            AccessDecisionRequest request,
            String accessPointCode,
            String reason
    ) {
        return new AccessDecisionResponse(
                request.badgeId(),
                request.accessPointId(),
                accessPointCode,
                request.accessTime(),
                false,
                "DENIED",
                null,
                reason
        );
    }

    private record AccessTarget(String accessPointCode, String scopeType, int targetId) {
    }
}
