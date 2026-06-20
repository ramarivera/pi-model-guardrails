// Containers pack — protections for Docker, Docker Compose, and Podman.
//
// Faithful port of THREE DCG container sub-packs collapsed into one Pack module:
//   - DCG `src/packs/containers/docker.rs`  (id "containers.docker")
//   - DCG `src/packs/containers/compose.rs` (id "containers.compose")
//   - DCG `src/packs/containers/podman.rs`  (id "containers.podman")
// (https://github.com/Dicklesworthstone/destructive_command_guard).
//
// The task contract is "one TS module -> one exported Pack", so the three DCG
// packs are merged here under id "containers", with safe/destructive patterns
// concatenated in DCG sub-pack order (docker -> compose -> podman). Declaration
// order is load-bearing (first-match-wins per text), and within each sub-pack
// the order matches DCG's `create_safe_patterns()` / `create_destructive_patterns()`.
//
// JS RegExp porting notes (same rules as the committed core packs):
//  - No POSIX `[[:alnum:]]`, no inline `(?i)` (case-sensitive => no "i" flag),
//    no possessive quantifiers.
//  - DCG's dual `regex` + `fancy_regex` engine collapses to one JS RegExp:
//    the `(?=\s|$)` trailing anchors, `(?!\s+.*(?:-v\b...))` negative
//    lookaheads, and `\$\(` subshell anchors port verbatim.
//  - Rust raw strings preserve backslashes; in JS regex literals `/` => `\/`.
//  - DCG severities: docker is mostly High with two Medium (image/container
//    prune); compose has Critical/High/Medium; podman has High/Critical/Medium.
//    Each rule below carries DCG's exact severity.

import type { DestructiveRule, Pack, SafeRule, Suggestion } from "../types.ts";

const ALL = "all" as const;

function s(command: string, description: string): Suggestion {
  // DCG `PatternSuggestion::new` defaults to `Platform::All`.
  return { command, description, platform: ALL };
}

// ============================================================================
// Suggestion constants (DCG: const *_SUGGESTIONS in docker.rs).
// ============================================================================

const SYSTEM_PRUNE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker system df -v",
    "Preview what would be removed without deleting anything",
  ),
  s(
    "docker system prune --filter 'until=24h'",
    "Only removes items older than 24 hours",
  ),
  s(
    "docker container prune",
    "Remove only stopped containers (preserves images and volumes)",
  ),
  s(
    "docker image prune",
    "Remove only dangling images (preserves containers and volumes)",
  ),
];

const VOLUME_PRUNE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker volume ls -q -f dangling=true",
    "List unused volumes first to review what would be deleted",
  ),
  s(
    "docker volume rm {volume-name}",
    "Remove specific volumes by name instead of all unused",
  ),
  s(
    "docker volume inspect {volume-name}",
    "Inspect volume contents and metadata before removal",
  ),
];

const NETWORK_PRUNE_SUGGESTIONS: Suggestion[] = [
  s("docker network ls", "List all networks to review before pruning"),
  s(
    "docker network rm {network-name}",
    "Remove specific networks by name instead of all unused",
  ),
];

const IMAGE_PRUNE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker images -f dangling=true",
    "List dangling images first to see what would be removed",
  ),
  s("docker rmi {image-id}", "Remove specific images by ID or tag"),
];

const CONTAINER_PRUNE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker ps -a -f status=exited",
    "List stopped containers first to review before removal",
  ),
  s(
    "docker rm {container-id}",
    "Remove specific containers instead of all stopped",
  ),
];

const RM_FORCE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker stop {container} && docker rm {container}",
    "Graceful shutdown with SIGTERM before removal",
  ),
  s(
    "docker container prune",
    "Remove stopped containers with confirmation prompt",
  ),
  s("docker ps -a | grep {container}", "Check container status before removal"),
];

const RMI_FORCE_SUGGESTIONS: Suggestion[] = [
  s(
    "docker rmi {image}",
    "Remove without force - fails safely if image is in use",
  ),
  s("docker image prune", "Remove only dangling (untagged) images"),
  s(
    "docker ps -a --filter ancestor={image}",
    "Check what containers are using the image first",
  ),
];

const VOLUME_RM_SUGGESTIONS: Suggestion[] = [
  s(
    "docker volume inspect {volume}",
    "Inspect volume metadata and mount point before removal",
  ),
  s(
    "docker run --rm -v {volume}:/data alpine ls -la /data",
    "List volume contents before deletion",
  ),
  s(
    "docker run --rm -v {volume}:/data -v $(pwd):/backup alpine tar czf /backup/backup.tar.gz /data",
    "Backup volume data before removal",
  ),
];

const STOP_ALL_SUGGESTIONS: Suggestion[] = [
  s("docker stop {container-name}", "Stop specific containers by name"),
  s(
    "docker stop $(docker ps -q -f name={pattern})",
    "Stop containers matching a name filter",
  ),
  s(
    "docker ps --format '{{.Names}}: {{.Status}}'",
    "List running containers before stopping",
  ),
];

// ============================================================================
// Long explanations (DCG: the multi-line explanation strings).
// ============================================================================

const SYSTEM_PRUNE_EXPLANATION =
  "docker system prune is Docker's most aggressive cleanup command. It removes:\n\n" +
  "- All stopped containers\n" +
  "- All networks not used by at least one container\n" +
  "- All dangling images (untagged)\n" +
  "- All dangling build cache\n\n" +
  "With -a flag, it also removes all unused images, not just dangling ones.\n" +
  "With --volumes flag, it removes all unused volumes (data loss!).\n\n" +
  "Preview what would be removed:\n  " +
  "docker system df          # Show disk usage\n  " +
  "docker system df -v       # Verbose with details\n\n" +
  "Safer alternative:\n  " +
  "docker container prune    # Only stopped containers\n  " +
  "docker image prune        # Only dangling images";

const VOLUME_PRUNE_EXPLANATION =
  "docker volume prune permanently deletes ALL volumes not currently attached " +
  "to a running container. This is extremely dangerous because:\n\n" +
  "- Database data stored in volumes is lost forever\n" +
  "- Application state and uploads are destroyed\n" +
  "- There is NO recovery mechanism\n\n" +
  "Even stopped containers' volumes are considered 'unused' and will be deleted.\n\n" +
  "Preview before pruning:\n  " +
  "docker volume ls                    # List all volumes\n  " +
  "docker volume ls -f dangling=true   # Show only unused\n\n" +
  "Safer approach:\n  " +
  "docker volume rm <specific-volume>  # Remove by name";

const NETWORK_PRUNE_EXPLANATION =
  "docker network prune removes all user-defined networks not used by any container. " +
  "While less destructive than volume prune, it can still cause issues:\n\n" +
  "- Custom network configurations are lost\n" +
  "- Containers may fail to communicate after restart\n" +
  "- Service discovery between containers breaks\n\n" +
  "Preview unused networks:\n  " +
  "docker network ls\n  " +
  "docker network ls -f dangling=true\n\n" +
  "Safer alternative:\n  " +
  "docker network rm <specific-network>";

const IMAGE_PRUNE_EXPLANATION =
  "docker image prune removes 'dangling' images (untagged layers). " +
  "With -a flag, it removes ALL images not used by existing containers.\n\n" +
  "Consequences:\n" +
  "- Build cache layers are deleted (slower rebuilds)\n" +
  "- With -a: base images must be re-pulled\n\n" +
  "Preview what would be removed:\n  " +
  "docker images -f dangling=true\n  " +
  "docker images                       # With -a flag\n\n" +
  "Usually safe, but may slow down builds.";

const CONTAINER_PRUNE_EXPLANATION =
  "docker container prune removes all stopped containers. This is relatively " +
  "safe but can cause issues:\n\n" +
  "- Container logs are lost\n" +
  "- Container filesystem layers are deleted\n" +
  "- Cannot restart or inspect removed containers\n\n" +
  "Preview stopped containers:\n  " +
  "docker ps -a -f status=exited\n  " +
  "docker ps -a -f status=created\n\n" +
  "Consider keeping recent containers for debugging.";

const DOCKER_RM_FORCE_EXPLANATION =
  "docker rm -f forcibly stops and removes containers. This is dangerous because:\n\n" +
  "- Running processes are killed immediately (SIGKILL)\n" +
  "- No graceful shutdown - data may be corrupted\n" +
  "- In-flight requests are dropped\n" +
  "- Uncommitted data in the container is lost\n\n" +
  "Safer approach:\n  " +
  "docker stop <container>  # Graceful shutdown (SIGTERM)\n  " +
  "docker rm <container>    # Then remove\n\n" +
  "Check container status first:\n  " +
  "docker ps -a | grep <container>";

const DOCKER_RMI_FORCE_EXPLANATION =
  "docker rmi -f forcibly removes images, even if containers are using them. " +
  "This can cause:\n\n" +
  "- Running containers to fail on restart\n" +
  "- Broken references to deleted layers\n" +
  "- Loss of build cache\n\n" +
  "Check what's using the image:\n  " +
  "docker ps -a --filter ancestor=<image>\n\n" +
  "Safer approach:\n  " +
  "docker rmi <image>  # Fails safely if in use";

const DOCKER_VOLUME_RM_EXPLANATION =
  "docker volume rm permanently deletes named volumes and all data stored in them. " +
  "This is irreversible:\n\n" +
  "- Database files are gone\n" +
  "- User uploads are lost\n" +
  "- Configuration data is destroyed\n" +
  "- No trash or undo mechanism exists\n\n" +
  "Check volume contents first:\n  " +
  "docker run --rm -v <volume>:/data alpine ls -la /data\n\n" +
  "Consider backing up:\n  " +
  "docker run --rm -v <volume>:/data -v $(pwd):/backup alpine \\\n    " +
  "tar czf /backup/volume-backup.tar.gz /data";

const STOP_ALL_EXPLANATION =
  "This pattern stops or kills ALL running containers on the system. " +
  "This is dangerous in shared environments:\n\n" +
  "- Production services go down\n" +
  "- Database connections are severed\n" +
  "- In-flight requests fail\n" +
  "- Other users' containers are affected\n\n" +
  "Be specific instead:\n  " +
  "docker stop <container-name>     # Stop by name\n  " +
  "docker stop $(docker ps -q -f name=myapp)  # Filter by name\n\n" +
  "Preview what would be stopped:\n  " +
  "docker ps --format '{{.Names}}: {{.Status}}'";

const COMPOSE_DOWN_VOLUMES_EXPLANATION =
  "The -v/--volumes flag causes docker-compose down to remove named volumes declared " +
  "in the volumes section of the Compose file, as well as anonymous volumes attached " +
  "to containers. This permanently destroys:\n\n" +
  "- Database data (PostgreSQL, MySQL, MongoDB volumes)\n" +
  "- User uploads and application state\n" +
  "- Any persistent configuration stored in volumes\n\n" +
  "Safer alternatives:\n" +
  "- docker-compose down: Stops and removes containers without touching volumes\n" +
  "- docker-compose stop: Stops containers, preserving everything\n" +
  "- docker volume ls: List volumes before removal";

const COMPOSE_DOWN_RMI_ALL_EXPLANATION =
  "The --rmi all flag removes all images used by services in the Compose file. " +
  "This forces re-downloading or rebuilding images on next 'up':\n\n" +
  "- Base images must be pulled again (bandwidth, time)\n" +
  "- Custom built images need rebuilding\n" +
  "- Layers not in registry are lost\n\n" +
  "Safer alternatives:\n" +
  "- docker-compose down: Preserves images for faster restarts\n" +
  "- docker-compose down --rmi local: Only removes images without custom tag\n" +
  "- docker image ls: Review images before removal";

const COMPOSE_RM_VOLUMES_EXPLANATION =
  "The -v flag with docker-compose rm removes anonymous volumes attached to the " +
  "containers being removed. This can cause data loss if volumes contain:\n\n" +
  "- Application state or session data\n" +
  "- Cached data that takes time to rebuild\n" +
  "- Temporary but important processing results\n\n" +
  "Safer alternatives:\n" +
  "- docker-compose rm: Removes containers without volumes\n" +
  "- docker-compose stop: Stops without removing anything\n" +
  "- docker volume ls: Check what volumes exist";

const COMPOSE_RM_FORCE_EXPLANATION =
  "The -f/--force flag removes containers without asking for confirmation. While " +
  "this doesn't directly cause data loss, it can be risky:\n\n" +
  "- Running containers are stopped abruptly (SIGKILL)\n" +
  "- No graceful shutdown for applications\n" +
  "- In-flight requests or transactions may be lost\n\n" +
  "Safer alternatives:\n" +
  "- docker-compose stop: Graceful shutdown first\n" +
  "- docker-compose rm: Asks for confirmation\n" +
  "- docker-compose ps: Check container status first";

const PODMAN_SYSTEM_PRUNE_EXPLANATION =
  "podman system prune is an aggressive cleanup command that removes:\n\n" +
  "- All stopped containers\n" +
  "- All pods without running containers\n" +
  "- All dangling images (untagged)\n" +
  "- All dangling build cache\n\n" +
  "With -a flag, removes ALL unused images. With --volumes, removes unused volumes.\n\n" +
  "Safer alternatives:\n" +
  "- podman system df: Preview disk usage first\n" +
  "- podman container prune: Only remove stopped containers\n" +
  "- podman image prune: Only remove dangling images";

const PODMAN_VOLUME_PRUNE_EXPLANATION =
  "podman volume prune permanently deletes ALL volumes not currently in use by " +
  "any container. This is extremely dangerous:\n\n" +
  "- Database data in volumes is lost forever\n" +
  "- Application state and uploads are destroyed\n" +
  "- Volumes from stopped containers are considered 'unused'\n" +
  "- No recovery mechanism exists\n\n" +
  "Safer alternatives:\n" +
  "- podman volume ls: List all volumes first\n" +
  "- podman volume inspect: Check volume contents\n" +
  "- podman volume rm <name>: Remove specific volumes";

const PODMAN_POD_PRUNE_EXPLANATION =
  "podman pod prune removes all pods that are not currently running. Pods group " +
  "containers together and pruning them:\n\n" +
  "- Removes all containers within the stopped pods\n" +
  "- Pod configuration and networking setup is lost\n" +
  "- Cannot restart or inspect removed pods\n\n" +
  "Safer alternatives:\n" +
  "- podman pod ps -a: List all pods first\n" +
  "- podman pod rm <pod>: Remove specific pods\n" +
  "- podman pod start <pod>: Restart instead of removing";

const PODMAN_IMAGE_PRUNE_EXPLANATION =
  "podman image prune removes dangling images (untagged layers). With -a flag, " +
  "removes ALL images not used by existing containers.\n\n" +
  "Consequences:\n" +
  "- Build cache layers are deleted (slower rebuilds)\n" +
  "- With -a: Base images must be re-pulled\n\n" +
  "Safer alternatives:\n" +
  "- podman images -f dangling=true: Preview what would be removed\n" +
  "- podman images: Review all images\n" +
  "- podman rmi <image>: Remove specific images";

const PODMAN_CONTAINER_PRUNE_EXPLANATION =
  "podman container prune removes all stopped containers. Relatively safe but:\n\n" +
  "- Container logs are lost\n" +
  "- Container filesystem layers are deleted\n" +
  "- Cannot restart or inspect removed containers\n\n" +
  "Safer alternatives:\n" +
  "- podman ps -a: List all containers first\n" +
  "- podman rm <container>: Remove specific containers\n" +
  "- podman start <container>: Restart instead of removing";

const PODMAN_RM_FORCE_EXPLANATION =
  "podman rm -f forcibly stops and removes containers. This is dangerous because:\n\n" +
  "- Running processes are killed immediately (SIGKILL)\n" +
  "- No graceful shutdown - data may be corrupted\n" +
  "- In-flight requests are dropped\n" +
  "- Uncommitted data in the container is lost\n\n" +
  "Safer alternatives:\n" +
  "- podman stop <container>: Graceful shutdown first\n" +
  "- podman rm <container>: Then remove\n" +
  "- podman ps: Check container status first";

const PODMAN_RMI_FORCE_EXPLANATION =
  "podman rmi -f forcibly removes images, even if containers reference them. " +
  "This can cause:\n\n" +
  "- Containers to fail on restart (missing image)\n" +
  "- Broken references to deleted layers\n" +
  "- Loss of build cache\n\n" +
  "Safer alternatives:\n" +
  "- podman ps -a --filter ancestor=<image>: Check what uses the image\n" +
  "- podman rmi <image>: Fails safely if in use\n" +
  "- podman images: Review images before removal";

const PODMAN_VOLUME_RM_EXPLANATION =
  "podman volume rm permanently deletes named volumes and all data stored in them. " +
  "This is irreversible:\n\n" +
  "- Database files are gone forever\n" +
  "- User uploads are lost\n" +
  "- Configuration data is destroyed\n" +
  "- No trash or undo mechanism\n\n" +
  "Safer alternatives:\n" +
  "- podman volume inspect <volume>: Check volume details\n" +
  "- podman run --rm -v vol:/data alpine ls -la /data: View contents\n" +
  "- Back up before removal";

// ---------------------------------------------------------------------------
// Safe patterns (allowed) — DCG docker -> compose -> podman
// `create_safe_patterns()`, in declaration order.
// ---------------------------------------------------------------------------

const safePatterns: SafeRule[] = [
  // ===== containers.docker safe patterns =====
  {
    name: "docker-ps",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-images",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-logs",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-inspect",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-build",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-pull",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-run",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-exec",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-stats",
    re: /^\s*docker\b(?:\s+--?\S+(?:\s+\S+)?)*\s+stats(?=\s|$)(?:\s+[^;&|`$()\s]+)*\s*$/,
  },
  {
    name: "docker-dry-run",
    re: /^\s*docker\b(?:\s+[^;&|`$()\s]+)*\s+--dry-run(?:\s+[^;&|`$()\s]+)*\s*$/,
  },

  // ===== containers.compose safe patterns =====
  {
    name: "compose-config",
    re: /(?:docker-compose|docker\s+compose)\s+config/,
  },
  { name: "compose-ps", re: /(?:docker-compose|docker\s+compose)\s+ps/ },
  { name: "compose-logs", re: /(?:docker-compose|docker\s+compose)\s+logs/ },
  { name: "compose-up", re: /(?:docker-compose|docker\s+compose)\s+up/ },
  { name: "compose-build", re: /(?:docker-compose|docker\s+compose)\s+build/ },
  { name: "compose-pull", re: /(?:docker-compose|docker\s+compose)\s+pull/ },
  {
    name: "compose-down-no-volumes",
    re: /(?:docker-compose|docker\s+compose)\s+down(?!\s+.*(?:-v\b|--volumes|--rmi))/,
  },

  // ===== containers.podman safe patterns =====
  { name: "podman-ps", re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+ps(?=\s|$)/ },
  {
    name: "podman-images",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+images(?=\s|$)/,
  },
  {
    name: "podman-logs",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+logs(?=\s|$)/,
  },
  {
    name: "podman-inspect",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+inspect(?=\s|$)/,
  },
  {
    name: "podman-build",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+build(?=\s|$)/,
  },
  {
    name: "podman-pull",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+pull(?=\s|$)/,
  },
  { name: "podman-run", re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+run(?=\s|$)/ },
  {
    name: "podman-exec",
    re: /podman\b(?:\s+--?\S+(?:\s+\S+)?)*\s+exec(?=\s|$)/,
  },
];

// ---------------------------------------------------------------------------
// Destructive patterns (blocked). Within a merged pack, first-match-wins is
// load-bearing. The DCG sub-packs were INDEPENDENT (docker / compose / podman),
// so there is no canonical inter-sub-pack order; the merge deliberately lists
// the MORE-SPECIFIC compose rules FIRST. A compose command (`docker-compose …`
// / `docker compose …`) also matches the broad docker `rm-force` etc. (because
// `docker\b.*?` bridges the `-compose`/` compose` suffix), so without
// compose-first the docker pack would intercept compose commands and mis-grade
// `docker-compose rm -f` (Medium per DCG) as docker `rm-force` (High). Putting
// compose first preserves each DCG sub-pack's canonical severity. Within each
// sub-pack the rule order is DCG's `create_destructive_patterns()` verbatim.
// ---------------------------------------------------------------------------

const destructivePatterns: DestructiveRule[] = [
  // ===== containers.compose destructive patterns (FIRST: most specific) =====
  {
    name: "down-volumes",
    re: /(?:docker-compose|docker\s+compose)\s+down\s+.*(?:-v\b|--volumes)/,
    severity: "critical",
    reason:
      "docker-compose down -v removes volumes and their data permanently.",
    explanation: COMPOSE_DOWN_VOLUMES_EXPLANATION,
  },
  {
    name: "down-rmi-all",
    re: /(?:docker-compose|docker\s+compose)\s+down\s+.*--rmi\s+all/,
    severity: "high",
    reason:
      "docker-compose down --rmi all removes all images used by services.",
    explanation: COMPOSE_DOWN_RMI_ALL_EXPLANATION,
  },
  {
    name: "rm-volumes",
    re: /(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-v\b|--volumes)/,
    severity: "high",
    reason: "docker-compose rm -v removes volumes attached to containers.",
    explanation: COMPOSE_RM_VOLUMES_EXPLANATION,
  },
  {
    name: "rm-force-compose",
    re: /(?:docker-compose|docker\s+compose)\s+rm\s+.*(?:-f\b|--force)/,
    severity: "medium",
    reason:
      "docker-compose rm -f forcibly removes containers without confirmation.",
    explanation: COMPOSE_RM_FORCE_EXPLANATION,
  },

  // ===== containers.docker destructive patterns =====
  {
    name: "system-prune",
    re: /docker\b.*?\bsystem\s+prune/,
    severity: "high",
    reason:
      "docker system prune removes ALL unused containers, networks, images. Use 'docker system df' to preview.",
    explanation: SYSTEM_PRUNE_EXPLANATION,
    suggestions: SYSTEM_PRUNE_SUGGESTIONS,
  },
  {
    name: "volume-prune",
    re: /docker\b.*?\bvolume\s+prune/,
    severity: "high",
    reason:
      "docker volume prune removes ALL unused volumes and their data permanently.",
    explanation: VOLUME_PRUNE_EXPLANATION,
    suggestions: VOLUME_PRUNE_SUGGESTIONS,
  },
  {
    name: "network-prune",
    re: /docker\b.*?\bnetwork\s+prune/,
    severity: "high",
    reason: "docker network prune removes ALL unused networks.",
    explanation: NETWORK_PRUNE_EXPLANATION,
    suggestions: NETWORK_PRUNE_SUGGESTIONS,
  },
  {
    name: "image-prune",
    re: /docker\b.*?\bimage\s+prune/,
    severity: "medium",
    reason:
      "docker image prune removes unused images. Use 'docker images' to review first.",
    explanation: IMAGE_PRUNE_EXPLANATION,
    suggestions: IMAGE_PRUNE_SUGGESTIONS,
  },
  {
    name: "container-prune",
    re: /docker\b.*?\bcontainer\s+prune/,
    severity: "medium",
    reason: "docker container prune removes ALL stopped containers.",
    explanation: CONTAINER_PRUNE_EXPLANATION,
    suggestions: CONTAINER_PRUNE_SUGGESTIONS,
  },
  {
    name: "rm-force",
    re: /docker\b.*?\brm\s+.*(?:-[a-zA-Z0-9]*f|--force)/,
    severity: "high",
    reason:
      "docker rm -f forcibly removes containers, potentially losing data.",
    explanation: DOCKER_RM_FORCE_EXPLANATION,
    suggestions: RM_FORCE_SUGGESTIONS,
  },
  {
    name: "rmi-force",
    re: /docker\b.*?\brmi\s+.*(?:-[a-zA-Z0-9]*f|--force)/,
    severity: "high",
    reason: "docker rmi -f forcibly removes images even if in use.",
    explanation: DOCKER_RMI_FORCE_EXPLANATION,
    suggestions: RMI_FORCE_SUGGESTIONS,
  },
  {
    name: "volume-rm",
    re: /docker\b.*?\bvolume\s+rm/,
    severity: "high",
    reason: "docker volume rm permanently deletes volumes and their data.",
    explanation: DOCKER_VOLUME_RM_EXPLANATION,
    suggestions: VOLUME_RM_SUGGESTIONS,
  },
  {
    name: "stop-all",
    re: /docker\b.*?\b(?:stop|kill)\s+\$\(/,
    severity: "high",
    reason:
      "Stopping/killing all containers can disrupt services. Be specific about which containers.",
    explanation: STOP_ALL_EXPLANATION,
    suggestions: STOP_ALL_SUGGESTIONS,
  },

  // ===== containers.podman destructive patterns =====
  {
    name: "podman-system-prune",
    re: /podman\b.*?\bsystem\s+prune/,
    severity: "high",
    reason:
      "podman system prune removes ALL unused containers, pods, images. Use 'podman system df' to preview.",
    explanation: PODMAN_SYSTEM_PRUNE_EXPLANATION,
  },
  {
    name: "podman-volume-prune",
    re: /podman\b.*?\bvolume\s+prune/,
    severity: "critical",
    reason:
      "podman volume prune removes ALL unused volumes and their data permanently.",
    explanation: PODMAN_VOLUME_PRUNE_EXPLANATION,
  },
  {
    name: "pod-prune",
    re: /podman\b.*?\bpod\s+prune/,
    severity: "medium",
    reason: "podman pod prune removes ALL stopped pods.",
    explanation: PODMAN_POD_PRUNE_EXPLANATION,
  },
  {
    name: "podman-image-prune",
    re: /podman\b.*?\bimage\s+prune/,
    severity: "medium",
    reason:
      "podman image prune removes unused images. Use 'podman images' to review first.",
    explanation: PODMAN_IMAGE_PRUNE_EXPLANATION,
  },
  {
    name: "podman-container-prune",
    re: /podman\b.*?\bcontainer\s+prune/,
    severity: "medium",
    reason: "podman container prune removes ALL stopped containers.",
    explanation: PODMAN_CONTAINER_PRUNE_EXPLANATION,
  },
  {
    name: "podman-rm-force",
    re: /podman\b.*?\brm\s+.*(?:-[a-zA-Z0-9]*f|--force)/,
    severity: "high",
    reason:
      "podman rm -f forcibly removes containers, potentially losing data.",
    explanation: PODMAN_RM_FORCE_EXPLANATION,
  },
  {
    name: "podman-rmi-force",
    re: /podman\b.*?\brmi\s+.*(?:-[a-zA-Z0-9]*f|--force)/,
    severity: "high",
    reason: "podman rmi -f forcibly removes images even if in use.",
    explanation: PODMAN_RMI_FORCE_EXPLANATION,
  },
  {
    name: "podman-volume-rm",
    re: /podman\b.*?\bvolume\s+rm/,
    severity: "high",
    reason: "podman volume rm permanently deletes volumes and their data.",
    explanation: PODMAN_VOLUME_RM_EXPLANATION,
  },
];

/**
 * Containers pack — merged DCG containers.docker + containers.compose +
 * containers.podman. `force` is NOT set (DCG container packs are config-gated,
 * not floor packs).
 *
 * Keywords are the union of the three sub-packs' keyword arrays in sub-pack
 * order (docker -> compose -> podman). Note the two DCG rule names that
 * collided across sub-packs were disambiguated to keep `${packId}:${ruleName}`
 * unique within this single merged pack:
 *   - compose `rm-force`  -> "rm-force-compose"  (docker already owns "rm-force")
 *   - podman  `system-prune`/`volume-prune`/`image-prune`/`container-prune`/
 *     `rm-force`/`rmi-force`/`volume-rm` -> "podman-"-prefixed
 *     (docker already owns the unprefixed names).
 * The regexes themselves are unchanged from DCG.
 *
 * Source: DCG `src/packs/containers/{docker,compose,podman}.rs` (`create_pack`).
 */
export const containersPack: Pack = {
  id: "containers",
  name: "Containers",
  description:
    "Protects against destructive Docker, Docker Compose, and Podman operations " +
    "like system/volume prune, down -v, and force removal",
  keywords: [
    // containers.docker
    "docker",
    "prune",
    "rmi",
    "volume",
    // containers.compose
    "docker-compose",
    "docker compose",
    "compose",
    // containers.podman
    "podman",
  ],
  safePatterns,
  destructivePatterns,
};
