using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.SignalR;
using System.Collections.Concurrent;
using UUIDNext;

[Authorize]
public class SignalingHub : Hub
{
    private readonly ILogger<SignalingHub> _logger;
    private static readonly ConcurrentDictionary<string, string> _mapping = new ConcurrentDictionary<string, string>();
    private ConcurrentBag<string> _groups = new ConcurrentBag<string>();

    public SignalingHub(ILogger<SignalingHub> logger)
    {
        _logger = logger;
    }

    public async Task JoinRoom(string roomId)
    {
        _logger.LogInformation(
            "Trying to join room {RoomId} from {ConnectionId}",
            roomId,
            Context.ConnectionId
        );
 
        if (!_mapping.TryGetValue(roomId, out var creatorConnectionId))
        {
            _logger.LogWarning("Room {RoomId} doesn't exist", roomId);
            return;
        }

        _logger.LogInformation(
            "Found creator connection {CreatorConnectionId} for room {RoomId}",
            creatorConnectionId,
            roomId
        );

        await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
        await Groups.AddToGroupAsync(creatorConnectionId, roomId);
        _groups.Add(roomId);

        await Clients.Client(creatorConnectionId).SendAsync("UserJoined");
    }

    public async Task CreateRoom()
    {
        var roomId = Uuid.NewRandom().ToString();
        _logger.LogInformation(
            "Creating room {RoomId} for {ConnectionId}",
            roomId,
            Context.ConnectionId
        );

        if (_mapping.TryAdd(roomId, Context.ConnectionId))
        {
            _logger.LogInformation("Room {RoomId} created successfully", roomId);
            await Groups.AddToGroupAsync(Context.ConnectionId, roomId);
            _groups.Add(roomId);
            await Clients.Caller.SendAsync("RoomCreated", roomId);
            return;
        }

        _logger.LogWarning("Room {RoomId} already exists", roomId);
    }

    public async Task SendSignal(string roomId, object signalData)
    {
        _logger.LogInformation(
            "Received signal in room {RoomId} from {ConnectionId}",
            roomId,
            Context.ConnectionId
        );
        _logger.LogInformation("Signal data: {SignalData}", signalData);

        // Send to all clients in the group except the sender
        await Clients.OthersInGroup(roomId).SendAsync("ReceiveSignal", signalData);
    }

    public override async Task OnDisconnectedAsync(Exception? exception)
    {
        var roomsToRemove = _mapping.Where(kvp => kvp.Value == Context.ConnectionId)
            .Select(kvp => kvp.Key)
            .ToList();

        foreach (var roomId in roomsToRemove)
        {
            _mapping.TryRemove(roomId, out _);
            _logger.LogInformation(
                "Removed room {RoomId} due to disconnect of {ConnectionId}",
                roomId,
                Context.ConnectionId
            );
        }

        await base.OnDisconnectedAsync(exception);
    }
}
